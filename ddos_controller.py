"""
Substrato os-ken (OpenFlow 1.3) da topologia em estrela: calcula as features de
cada switch, entrega ao agente daquele switch pela bridge e aplica, só naquele
switch, a mitigação que o agente decidir.

  cd jade && ./run.sh hybrid 7070 3
  EDGES=3 REASONING_PORT=7070 osken-manager ddos_controller.py
  sudo python3 mininet_topology.py

dpid 1..N são as bordas (domínios 0..N-1); dpid N+1 é o central (domínio N).
"""

import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4
from os_ken.lib import hub

from detection_core import (Baseline, features_from_flow_stats,
                            calibrate_from_flow_stats)
from bridge.client import ReasoningClient

CALIBRATION_SECONDS = 10
MITIGATION_PRIORITY = 100
MONITOR_FLOW_PRIORITY = 10
FLOW_IDLE_TIMEOUT = 5
# rate_limit usa meters OpenFlow em pacotes/s (OVS >= 2.8)
RATE_LIMIT_PPS = 100
RATE_LIMIT_METER_ID = 1
# drop e rate_limit copiam cada pacote ao controlador (só contagem); sem isso os
# agentes deixam de ver o tráfego mitigado e nunca encerram a mitigação
MITIGATION_COOKIE = 0x64
# scrubbing desvia o tráfego ao controlador, que só repassa origens vistas na calibração
SCRUB_COOKIE = 0x65
EDGES = int(os.environ.get("EDGES", "3"))
# respostas dos servidores ficam fora das medidas, como no gerador sintético, que só
# modela o tráfego em direção aos destinos; sem isso o drop zera a entropia de destinos
SERVERS = set(filter(None, os.environ.get("SERVERS", "").split(",")))


class DDoSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.tick = 0
        self.mitigated = defaultdict(dict)
        self._meters_installed = set()
        # um domínio (e um agente) por switch
        self.domain_of = {}
        self.baselines = {}
        self.dp_of = {}

        # PACKET_IN também conta, senão o --rand-source do hping3 não soma volume
        self.pktin = defaultdict(lambda: defaultdict(int))
        self.flow_delta = defaultdict(lambda: defaultdict(int))
        self.prev_counts = {}
        self.known_src = defaultdict(set)

        host = os.environ.get("REASONING_HOST", "127.0.0.1")
        port = int(os.environ.get("REASONING_PORT", "7070"))
        self.reasoning = ReasoningClient(host, port)
        try:
            self.reasoning.connect()
            self.reasoning.reset("mininet")
            self.logger.info("Conectado à camada de raciocínio em %s:%d", host, port)
        except OSError as e:
            self.reasoning = None
            self.logger.warning("Camada de agentes indisponível em %s:%d (%s); "
                                "só as medidas serão registradas, sem mitigação. "
                                "Suba antes com 'cd jade && ./run.sh bdi %d'.",
                                host, port, e, port)

        self.metrics_file = open("substrate_features.csv", "a", buffering=1)
        if os.path.getsize("substrate_features.csv") == 0:
            self.metrics_file.write("t,pps,src_entropy,dst_entropy,over_usage,"
                                    "anomalous_usage,fanin,zscore,threat,action\n")

        self.events = open("mitigacoes.csv", "a", buffering=1)
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        if datapath.id not in self.domain_of:
            d = datapath.id - 1 if datapath.id <= EDGES else EDGES
            self.domain_of[datapath.id] = d
            self.dp_of[d] = datapath
            self.baselines[d] = Baseline()
            self.logger.info("Switch %s -> domínio %d (%s)", datapath.id, d,
                             "central" if d == EDGES else "borda")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            self.pktin[dpid][(ip_pkt.src, ip_pkt.dst)] += 1
            if msg.cookie == MITIGATION_COOKIE:
                return
            if msg.cookie == SCRUB_COOKIE:
                if ip_pkt.src not in self.known_src[dpid]:
                    return
            elif out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                self._add_flow(datapath, MONITOR_FLOW_PRIORITY, match, actions,
                               idle_timeout=FLOW_IDLE_TIMEOUT)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        # janela de 1 s de relógio: o processamento não alonga a janela
        next_t = time.monotonic()
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            next_t += 1
            hub.sleep(max(0.0, next_t - time.monotonic()))
            self._run_cycle()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            src_ip = stat.match.get('ipv4_src')
            dst_ip = stat.match.get('ipv4_dst')
            if not (src_ip and dst_ip):
                continue
            key = (dpid, src_ip, dst_ip)
            prev = self.prev_counts.get(key, stat.packet_count)
            delta = stat.packet_count - prev
            if delta < 0:
                delta = stat.packet_count
            self.prev_counts[key] = stat.packet_count
            if delta > 0:
                self.flow_delta[dpid][(src_ip, dst_ip)] += delta

    def _collect_records(self, dpid):
        merged = defaultdict(int)
        for k, n in self.pktin[dpid].items():
            merged[k] += n
        for k, n in self.flow_delta[dpid].items():
            merged[k] += n
        for k in [k for k in merged if k[0] in SERVERS]:
            del merged[k]
        self.pktin[dpid].clear()
        self.flow_delta[dpid].clear()
        return [{"src_ip": s, "dst_ip": d, "packet_count": n}
                for (s, d), n in merged.items()]

    def _run_cycle(self):
        if not self.domain_of:
            return
        self.tick += 1
        t = self.tick
        calibrating = t <= CALIBRATION_SECONDS

        any_records = False
        for dpid, domain in self.domain_of.items():
            records = self._collect_records(dpid)
            if calibrating:
                if records:
                    any_records = True
                    calibrate_from_flow_stats(self.baselines[domain], records)
                    self.known_src[dpid].update(r["src_ip"] for r in records)
                continue
            # todo domínio recebe medidas a cada janela, mesmo sem tráfego, como no soak:
            # sem elas a suspeita do BDI não decai e a mitigação nunca é liberada
            f = features_from_flow_stats(records, self.baselines[domain])
            self.logger.info("[t=%d dom=%d] pps=%s over=%s anom=%s fanin=%s z=%s",
                             t, domain, f["pps"], f["over_usage"],
                             f["anomalous_usage"], f["fanin"], f["zscore"])
            if self.reasoning is not None:
                try:
                    self.reasoning.send_features(t, domain, f)
                except OSError as e:
                    self.logger.warning("Raciocínio caiu (%s) -- sem mitigação.", e)
                    self.reasoning = None
            self.metrics_file.write(
                f"{t},{f['pps']},{f['src_entropy']},{f['dst_entropy']},"
                f"{f['over_usage']},{f['anomalous_usage']},{f['fanin']},"
                f"{f['zscore']},{f['threat']},\n")

        if calibrating and any_records:
            self.logger.info("[t=%d] calibrando baselines dos domínios...", t)
            return

        if self.reasoning is not None:
            try:
                self._fault_command()
                for msg in self.reasoning.drain():
                    if msg.get("type") == "telemetry" and msg.get("event") == "adopted":
                        d = msg["domain"]
                        self.reasoning.switch_state(d, sorted(self.mitigated[d]))
                        continue
                    if msg.get("type") != "decision":
                        continue
                    action, target, d = msg.get("action", ""), msg.get("target"), msg.get("domain")
                    if action == "MITIGATE" and target:
                        self._install_mitigation(d, target, msg.get("strategy") or "drop")
                    elif action == "RESTORE" and target:
                        self._remove_mitigation(d, target)
            except OSError as e:
                self.logger.warning("Raciocínio caiu (%s) -- sem mitigação.", e)
                self.reasoning = None

    def _fault_command(self):
        # injeção de falha na validação: o orquestrador escreve "kill d" ou "spawn d" em falha.cmd
        if not os.path.exists("falha.cmd"):
            return
        with open("falha.cmd") as fh:
            cmd = fh.read().split()
        os.remove("falha.cmd")
        if len(cmd) == 2 and cmd[0] in ("kill", "spawn"):
            self.logger.warning("*** FALHA: %s agente do domínio %s ***", cmd[0], cmd[1])
            (self.reasoning.kill_agent if cmd[0] == "kill" else self.reasoning.spawn_agent)(int(cmd[1]))

    def _ensure_meter(self, dp):
        if dp.id in self._meters_installed:
            return
        self._meters_installed.add(dp.id)
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        band = parser.OFPMeterBandDrop(rate=RATE_LIMIT_PPS,
                                       burst_size=RATE_LIMIT_PPS // 10)
        mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_ADD,
                                 flags=ofproto.OFPMF_PKTPS | ofproto.OFPMF_BURST,
                                 meter_id=RATE_LIMIT_METER_ID, bands=[band])
        dp.send_msg(mod)

    def _install_mitigation(self, domain, target_ip, strategy="drop"):
        dp = self.dp_of.get(domain)
        if dp is None or self.mitigated[domain].get(target_ip) == strategy:
            return
        if target_ip in self.mitigated[domain]:
            self._remove_mitigation(domain, target_ip)
        self.mitigated[domain][target_ip] = strategy
        self.events.write(f"{time.time():.3f},{domain},{target_ip},{strategy}\n")
        self.logger.warning("*** MITIGAÇÃO (%s) para %s no domínio %d ***", strategy, target_ip, domain)
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=target_ip)
        copy_to_ctl = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])
        if strategy == "rate_limit":
            # tabela 0 copia ao controlador e segue para a 1, onde o meter limita
            self._ensure_meter(dp)
            inst = [parser.OFPInstructionMeter(RATE_LIMIT_METER_ID),
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                        [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])]
            dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=1, priority=MITIGATION_PRIORITY,
                                          match=match, instructions=inst))
            dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=MITIGATION_PRIORITY,
                                          cookie=MITIGATION_COOKIE, match=match,
                                          instructions=[copy_to_ctl, parser.OFPInstructionGotoTable(1)]))
        elif strategy == "scrubbing":
            dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=MITIGATION_PRIORITY,
                                          cookie=SCRUB_COOKIE, match=match,
                                          instructions=[copy_to_ctl]))
        else:
            dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=MITIGATION_PRIORITY,
                                          cookie=MITIGATION_COOKIE, match=match,
                                          instructions=[copy_to_ctl]))

    def _remove_mitigation(self, domain, target_ip):
        dp = self.dp_of.get(domain)
        if dp is None or self.mitigated[domain].pop(target_ip, None) is None:
            return
        self.logger.info("*** Mitigação encerrada para %s no domínio %d ***", target_ip, domain)
        self.events.write(f"{time.time():.3f},{domain},{target_ip},restore\n")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=target_ip)
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofproto.OFPFC_DELETE,
                                      table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                      priority=MITIGATION_PRIORITY, match=match))
