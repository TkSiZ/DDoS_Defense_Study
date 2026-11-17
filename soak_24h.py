"""
Teste de longa duração na topologia em estrela: N switches de borda e um
switch central junto da vítima. As 3 arquiteturas rodam em paralelo (3 JADE,
3 portas) e recebem o mesmo tráfego nas bordas; o central de cada uma vê o que
as bordas daquela arquitetura deixaram passar.

Uma janela = --interval segundos de tráfego (padrão 1 s). Mitigações decididas
em uma janela valem a partir da seguinte. Tempos em ms vêm do relógio da máquina
(Python e Java compartilham o mesmo relógio).

Uso: python3 soak_24h.py --tag r1 [--hours 24] [--edges 3] [--fault-prob 0.3] [--seed 1]
Saídas (prefixo soak_<tag>_):
  episodes.csv    uma linha por episódio x arquitetura
  windows.csv.gz  features e mitigação de cada janela x arquitetura x switch
  summary.csv     snapshots periódicos
  meta.json       parâmetros da rodada
  <arch>.log      log do JADE
"""

import argparse
import csv
import gzip
import hashlib
import json
import os
import platform
import random
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

import detection_core
import scenarios as sc
from detection_core import Baseline, features_from_packets, calibrate_from_packets

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bridge"))
from client import ReasoningClient  # noqa: E402
from jade_runner import start_jade, stop_jade  # noqa: E402

ARCHS = ["eca", "bdi", "hybrid"]
BASE_PORT = int(os.environ.get("SOAK_PORT", "7110"))
FEATURE_COLS = ["pps", "src_entropy", "dst_entropy", "src_rise", "dst_drop",
                "fanin", "zscore", "over_usage", "anomalous_usage", "threat", "target_ip"]

_stop = {"flag": False}


def _sigint(signum, frame):
    print("\n[soak] interrupção -- encerrando com segurança...")
    _stop["flag"] = True


def now_ms():
    return time.time() * 1000


def _slept():
    """Tempo em suspensão desde o boot: BOOTTIME conta a suspensão, MONOTONIC não.
    Ajustes do relógio de parede (NTP) não o alteram."""
    return time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()


class ArchRunner:

    def __init__(self, arch, port, tag, edges, extra_env):
        self.arch = arch
        self.port = port
        self.tag = tag
        self.edges = edges
        self.center = edges
        self.env = extra_env
        self.proc = self.log = self.client = None
        self.up = False
        self.last_restart = 0.0
        self.acl = 0
        self.rules = defaultdict(dict)
        self.sent_ms = {}
        self.kill_ms = None
        self.killed = None
        self.new_episode(set())

    def new_episode(self, targets):
        self.targets = targets
        self.e = defaultdict(float)
        self.e["acl0"] = self.acl
        self.e_detect = None
        self.e_detect_ms = None
        self.e_evidence_tick = None
        self.e_detector = None
        self.e_det_tick = None
        self.e_det_strategy = None
        self.e_strategy = None
        self.e_adopted_ms = None
        self.e_adopter = None
        self.killed = None
        self.kill_ms = None

    def start(self):
        self.proc, self.log = start_jade(self.arch, self.port,
                                         f"soak_{self.tag}_{self.arch}.log",
                                         env=self.env, edges=self.edges)
        self.client = ReasoningClient("127.0.0.1", self.port).connect()
        self.client.reset("soak")
        self.rules.clear()
        self.up = True

    def stop(self):
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        if self.proc:
            stop_jade(self.proc, self.log)
        self.up = False

    def ensure_up(self, now, cooldown=60):
        if self.up or now - self.last_restart < cooldown:
            return
        self.last_restart = now
        try:
            print(f"[soak] reiniciando camada '{self.arch}'...")
            self.stop()
            self.start()
        except Exception as e:
            print(f"[soak] falha ao reiniciar '{self.arch}': {e}")
            self.up = False

    def mitigating(self, d, targets):
        return any(t in self.rules[d] for t in targets)

    def process(self, tick, feats, attack_phase):
        if not self.up:
            return
        try:
            self.sent_ms[tick] = now_ms()
            for d, f in feats.items():
                self.client.send_features(tick, d, f)
            for m in self.client.drain(max_wait=0.2):
                ts = m.get("ts_ms", m.get("_rx_ms"))
                if m.get("type") == "telemetry":
                    self.acl = m.get("acl_msgs", self.acl)
                    if m.get("event") == "adopted":
                        d = m["domain"]
                        self.client.switch_state(d, sorted(self.rules[d]))
                        if self.kill_ms is not None and self.e_adopted_ms is None and d == self.killed:
                            self.e_adopted_ms = ts
                            self.e_adopter = m.get("by")
                elif m.get("type") == "decision":
                    d, t = m.get("domain"), m.get("target")
                    if m.get("action") == "MITIGATE":
                        self.rules[d][t] = m.get("strategy") or "drop"
                        if attack_phase and t in self.targets:
                            if self.e_detect is None:
                                self.e_detect = tick
                                self.e_detect_ms = ts
                                self.e_evidence_tick = m.get("tick")
                                self.e_strategy = m.get("strategy")
                            if self.e_detector is None and m.get("cause") == "local":
                                self.e_detector = d
                                self.e_det_tick = m.get("tick")
                                self.e_det_strategy = m.get("strategy")
                    elif m.get("action") == "RESTORE":
                        self.rules[d].pop(t, None)
        except OSError:
            print(f"[soak] camada '{self.arch}' caiu -- marcando para reinício.")
            self.up = False


def _git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True,
                              text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


def _provenance():
    h = {}
    for f in sorted(os.listdir(HERE)):
        if f.endswith((".py", ".sh")):
            with open(os.path.join(HERE, f), "rb") as fh:
                h[f] = hashlib.sha256(fh.read()).hexdigest()[:16]
    classes = hashlib.sha256()
    for root, _, files in sorted(os.walk(os.path.join(HERE, "jade", "classes"))):
        for f in sorted(files):
            with open(os.path.join(root, f), "rb") as fh:
                classes.update(fh.read())
    try:
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=HERE,
                                    capture_output=True, text=True, timeout=5).stdout.strip())
    except Exception:
        dirty = None
    return {"git_dirty": dirty, "files_sha256": h, "jade_classes_sha256": classes.hexdigest()[:16]}


def _csv(path, header):
    fh = open(path, "a", newline="", buffering=1)
    w = csv.writer(fh)
    if os.path.getsize(path) == 0:
        w.writerow(header)
    return fh, w


def _floats(s):
    return [float(a) for a in s.split(",") if a.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="pilot", help="nome da rodada (prefixo dos arquivos)")
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("--interval", type=float, default=1.0, help="segundos por janela")
    ap.add_argument("--edges", type=int, default=3)
    ap.add_argument("--normal-min", type=int, default=30)
    ap.add_argument("--normal-max", type=int, default=90)
    ap.add_argument("--attack-min", type=int, default=10)
    ap.add_argument("--attack-max", type=int, default=30)
    ap.add_argument("--spike-prob", type=float, default=0.25,
                    help="prob. de um pico legítimo entre episódios")
    ap.add_argument("--vectors", default=",".join(sc.VECTORS_SEEN + sc.VECTORS_NEW))
    ap.add_argument("--full-prob", type=float, default=0.5,
                    help="prob. de um ataque vir na intensidade nominal (alpha = 1)")
    ap.add_argument("--alphas", default="0.75,0.5,0.25,0.12",
                    help="intensidades sorteadas para os demais ataques")
    ap.add_argument("--spike-alphas", default="1,0.75,0.5,0.25,0.12")
    ap.add_argument("--fault-prob", type=float, default=0.3,
                    help="prob. de um ataque derrubar um agente (recriado no fim do episódio)")
    ap.add_argument("--kill-center-prob", type=float, default=0.25,
                    help="prob. de a falha atingir o central em vez de uma borda")
    ap.add_argument("--comms", choices=["on", "off"], default="on",
                    help="off desliga os alertas entre agentes (ablação)")
    ap.add_argument("--calib", type=int, default=120, help="janelas de calibração")
    ap.add_argument("--summary-every", type=int, default=600, help="segundos")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    if args.seed is not None:
        random.seed(args.seed)
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)
    signal.signal(signal.SIGHUP, _sigint)

    ne = args.edges
    center = ne
    vectors = [v.strip() for v in args.vectors.split(",") if v.strip()]
    alphas = _floats(args.alphas)
    spike_alphas = _floats(args.spike_alphas)
    prefix = f"soak_{args.tag}_"
    old = [prefix + s for s in ("episodes.csv", "windows.csv.gz", "summary.csv", "meta.json")
           if os.path.exists(prefix + s)]
    if old:
        sys.exit(f"[soak] {', '.join(old)} já existe; mova antes de rodar '{args.tag}' de novo.")
    env = {"MAS_COMMS": args.comms}
    runners = [ArchRunner(a, BASE_PORT + i, args.tag, ne, env) for i, a in enumerate(ARCHS)]
    # o gerador global só produz tráfego; assim as decisões dos agentes não alteram a sequência
    fault_rng = random.Random(None if args.seed is None else f"{args.seed}-falhas")
    mit_rng = {r.arch: random.Random(None if args.seed is None else f"{args.seed}-{r.arch}") for r in runners}
    eb = [Baseline() for _ in range(ne)]
    cb = Baseline()

    meta = {
        "tag": args.tag, "started": datetime.now().isoformat(timespec="seconds"),
        "window_ms": args.interval * 1000, "args": vars(args), "git_commit": _git_commit(), **_provenance(),
        "host": platform.node(), "python": platform.python_version(),
        "topology": {"edges": ne, "center_domain": center},
        "vectors_seen_in_design": sc.VECTORS_SEEN, "vectors_new": sc.VECTORS_NEW,
        "detection": {k: getattr(detection_core, k) for k in
                      ("PPS_K", "SRC_ENTROPY_RISE_THRESHOLD",
                       "DST_ENTROPY_DROP_THRESHOLD", "ZSCORE_THRESHOLD")},
        "rate_limit_pps": sc.RATE_LIMIT_PPS,
        "bdi_env": {k: os.environ.get(k) for k in
                    ("BDI_DECAY", "BDI_GOAL", "BDI_RELEASE", "BDI_DROP_CONF", "BDI_PEER")},
    }

    epi_f, epi_w = _csv(prefix + "episodes.csv", [
        "timestamp", "episode", "kind", "vector", "alpha", "duration_s", "architecture",
        "detected", "detector", "detector_role", "latency_ticks", "latency_evidence_ticks",
        "latency_ms", "strategy", "attack_pkts", "attack_leaked", "legit_pkts", "legit_blocked",
        "coverage", "fp_windows", "fp_edge_windows", "fp_center_windows", "acl_delta",
        "killed_domain", "killed_role", "adopted", "adopter", "recovery_ms",
        "detector_tick", "detector_strategy", "down_windows", "fault_planned"])
    sum_f, sum_w = _csv(prefix + "summary.csv", [
        "timestamp", "elapsed_h", "architecture", "up", "attacks", "detected",
        "detect_rate", "spike_fp_windows", "normal_fp_windows", "total_acl"])
    win_path = prefix + "windows.csv.gz"
    new_win = not os.path.exists(win_path)
    win_fh = gzip.open(win_path, "at", newline="")
    win_w = csv.writer(win_fh)
    if new_win:
        win_w.writerow(["tick", "t_ms", "architecture", "phase", "episode", "vector", "subvector",
                        "alpha", "domain", "role"] + FEATURE_COLS
                       + ["rule_on_target", "attack_pkts", "attack_leaked", "legit_pkts",
                          "legit_blocked", "acl"])

    agg = {a: defaultdict(float) for a in ARCHS}

    print(f"[soak] '{args.tag}': {ne} bordas + central, comunicação {args.comms}; "
          f"subindo as 3 camadas JADE (portas {BASE_PORT}..{BASE_PORT+2})...")
    for r in runners:
        try:
            r.start()
            print(f"  '{r.arch}' no ar (porta {r.port}).")
        except Exception as e:
            print(f"  '{r.arch}' FALHOU ao subir: {e}")

    t0 = time.time()
    m0 = time.monotonic()
    deadline = m0 + args.hours * 3600
    last_summary = m0
    tick = 0
    episode_id = 0

    phase = "calib"
    phase_left = args.calib
    episode = None
    crowd = None
    vector = None
    alpha = None
    atk_local = 0
    attack_start_tick = 0
    epi_start_wall = m0
    fault_episode = False
    fault_done = False
    fault_domain = None

    def start_attack():
        nonlocal phase, phase_left, vector, alpha, atk_local, episode_id, episode
        nonlocal epi_start_wall, attack_start_tick, fault_episode, fault_done, fault_domain
        episode_id += 1
        vector = random.choice(vectors)
        alpha = 1.0 if random.random() < args.full_prob else random.choice(alphas)
        phase = "attack"
        phase_left = random.randint(args.attack_min, args.attack_max)
        episode = sc.AttackEpisode(vector, alpha, ne, phase_left)
        atk_local = 0
        attack_start_tick = tick
        epi_start_wall = time.monotonic()
        fault_episode = random.random() < args.fault_prob
        fault_done = False
        fault_domain = center if fault_rng.random() < args.kill_center_prob else fault_rng.randrange(ne)
        for r in runners:
            r.new_episode(episode.targets())
        print(f"[{datetime.now():%H:%M:%S}] episódio {episode_id}: ATAQUE '{vector}' "
              f"alpha={alpha} ({phase_left}s)" + (" + falha" if fault_episode else ""))

    def start_spike():
        nonlocal phase, phase_left, episode_id, epi_start_wall, alpha, crowd, vector
        episode_id += 1
        phase = "spike"
        vector = ""
        phase_left = random.randint(5, 12)
        epi_start_wall = time.monotonic()
        alpha = random.choice(spike_alphas)
        crowd = sc.FlashCrowd(alpha, ne)
        for r in runners:
            r.new_episode({sc.VICTIM_IP})
        print(f"[{datetime.now():%H:%M:%S}] episódio {episode_id}: PICO LEGÍTIMO "
              f"alpha={alpha} ({phase_left}s)")

    def row_common(r, kind, dur):
        return [datetime.now().isoformat(timespec="seconds"), episode_id, kind, vector, alpha,
                dur, r.arch]

    def end_attack():
        dur = round(time.monotonic() - epi_start_wall, 1)
        for r in runners:
            e = r.e
            detected = r.e_detect is not None
            lat = (r.e_detect - attack_start_tick) if detected else ""
            t_first = r.sent_ms.get(attack_start_tick + 1)
            lat_ms = (round(r.e_detect_ms - t_first, 1)
                      if detected and t_first and r.e_detect_ms else "")
            lat_ev = ""
            if detected and r.e_evidence_tick is not None and r.e_evidence_tick >= 0:
                lat_ev = r.e_evidence_tick - attack_start_tick
            role = ("central" if r.e_detector == center else "borda") if r.e_detector is not None else ""
            det_tick = (r.e_det_tick - attack_start_tick
                        if r.e_det_tick is not None and r.e_det_tick >= 0 else "")
            killed_role = ("central" if r.killed == center else "borda") if r.killed is not None else ""
            rec_ms = (round(r.e_adopted_ms - r.kill_ms, 1)
                      if r.kill_ms and r.e_adopted_ms else "")
            epi_w.writerow(row_common(r, "attack", dur) + [
                detected, r.e_detector if r.e_detector is not None else "", role, lat, lat_ev, lat_ms,
                r.e_strategy or "", int(e["atk"]), int(e["atk_leak"]), int(e["leg"]),
                int(e["leg_block"]), round(e["cov"] / max(1, e["windows"]), 3),
                "", "", "", r.acl - e["acl0"],
                r.killed if r.killed is not None else "", killed_role,
                (r.e_adopted_ms is not None) if r.killed is not None else "",
                r.e_adopter if r.e_adopter is not None else "", rec_ms,
                det_tick, r.e_det_strategy or "", int(e["down"]),
                fault_domain if fault_episode else ""])
            agg[r.arch]["attacks"] += 1
            agg[r.arch]["detected"] += int(detected)
            r.sent_ms.clear()
            if r.killed is not None and r.up:
                try:
                    r.client.spawn_agent(r.killed)
                except OSError:
                    pass

    def end_spike():
        dur = round(time.monotonic() - epi_start_wall, 1)
        for r in runners:
            e = r.e
            epi_w.writerow(row_common(r, "spike", dur) + [
                "", "", "", "", "", "", "", 0, 0, int(e["leg"]), int(e["leg_block"]), "",
                int(e["fp"]), int(e["fp_edge"]), int(e["fp_center"]), r.acl - e["acl0"],
                "", "", "", "", "", "", "", int(e["down"]), ""])
            agg[r.arch]["spike_fp"] += e["fp"]

    jump = False
    slept0 = _slept()
    while not _stop["flag"] and time.monotonic() < deadline:
        if _slept() - slept0 > 5:
            # a máquina dormiu: as janelas seguintes não são contínuas e a rodada não vale
            print(f"\n[soak] MÁQUINA SUSPENSA por {_slept() - slept0:.0f} s; rodada interrompida.")
            jump = True
            break
        now = time.time()
        mono = time.monotonic()

        if phase_left <= 0:
            if phase == "attack":
                end_attack()
            elif phase == "spike":
                end_spike()
            if phase in ("attack", "spike"):
                phase = "normal"
                vector, alpha = "", ""
                phase_left = random.randint(args.normal_min, args.normal_max)
            else:
                if random.random() < args.spike_prob:
                    start_spike()
                else:
                    start_attack()

        edge_pk = {d: sc.background(d) for d in range(ne)}
        subvector = ""
        if phase == "attack":
            subvector = episode.current(atk_local)[0]
            for d in range(ne):
                edge_pk[d] += episode.edge_packets(d, atk_local)
            atk_local += 1
        elif phase == "spike":
            for d in range(ne):
                edge_pk[d] += crowd.edge_packets(d)

        if phase == "calib":
            for d in range(ne):
                calibrate_from_packets(eb[d], edge_pk[d])
            calibrate_from_packets(cb, [p for d in range(ne) for p in edge_pk[d]])
            phase_left -= 1
            tick += 1
            if phase_left <= 0:
                meta["edge_pps_threshold"] = [round(b.pps_threshold(), 1) for b in eb]
                meta["center_pps_threshold"] = round(cb.pps_threshold(), 1)
                with open(prefix + "meta.json", "w") as fh:
                    json.dump(meta, fh, indent=2, ensure_ascii=False)
                print(f"[soak] calibrado: limiar de volume bordas {meta['edge_pps_threshold']}, "
                      f"central {meta['center_pps_threshold']}")
            time.sleep(max(0, args.interval - (time.monotonic() - mono)))
            continue

        tick += 1
        t_ms = round(now_ms(), 1)
        edge_f = {d: features_from_packets(edge_pk[d], eb[d]) for d in range(ne)}
        targets = episode.targets() if phase == "attack" else {sc.VICTIM_IP}
        ep = episode_id if phase in ("attack", "spike") else ""

        for r in runners:
            r.ensure_up(mono)
            residual = []
            for d in range(ne):
                residual += sc.apply_mitigation(edge_pk[d], r.rules[d], rng=mit_rng[r.arch])
            center_f = features_from_packets(residual, cb)
            delivered = sc.apply_mitigation(residual, r.rules[center], rng=mit_rng[r.arch])

            sent_atk = sum(1 for d in range(ne) for p in edge_pk[d] if p["atk"] and p["dst_ip"] in targets)
            sent_leg = sum(1 for d in range(ne) for p in edge_pk[d] if not p["atk"] and p["dst_ip"] in targets)
            got_atk = sum(1 for p in delivered if p["atk"] and p["dst_ip"] in targets)
            got_leg = sum(1 for p in delivered if not p["atk"] and p["dst_ip"] in targets)

            e = r.e
            e["windows"] += 1
            e["down"] += int(not r.up)
            e["atk"] += sent_atk
            e["atk_leak"] += got_atk
            e["leg"] += sent_leg
            e["leg_block"] += sent_leg - got_leg
            e["cov"] += sum(r.mitigating(d, targets) for d in range(ne)) / ne
            fp_edge = any(r.mitigating(d, targets) for d in range(ne))
            fp_center = r.mitigating(center, targets)
            if phase == "spike":
                e["fp"] += int(fp_edge or fp_center)
                e["fp_edge"] += int(fp_edge)
                e["fp_center"] += int(fp_center)
            elif phase == "normal" and (fp_edge or fp_center):
                agg[r.arch]["normal_fp"] += 1

            feats = dict(edge_f)
            feats[center] = center_f
            for d in range(ne + 1):
                f = feats[d]
                win_w.writerow([tick, t_ms, r.arch, phase, ep, vector, subvector, alpha, d,
                                "central" if d == center else "borda"]
                               + [f.get(c) for c in FEATURE_COLS]
                               + [",".join(sorted(f"{t}:{s}" for t, s in r.rules[d].items()
                                                  if t in targets)),
                                  sent_atk, got_atk, sent_leg, sent_leg - got_leg, r.acl])
            r.process(tick, feats, phase == "attack")

        if phase == "attack" and fault_episode and not fault_done and atk_local >= 3:
            for r in runners:
                if not r.up:
                    continue
                r.killed = fault_domain
                r.kill_ms = now_ms()
                try:
                    r.client.kill_agent(fault_domain)
                except OSError:
                    pass
            fault_done = True

        phase_left -= 1

        if mono - last_summary >= args.summary_every:
            last_summary = mono
            win_fh.flush()
            ts = datetime.now().isoformat(timespec="seconds")
            eh = round((mono - m0) / 3600, 3)
            for r in runners:
                a = r.arch
                atks = agg[a]["attacks"]
                det = agg[a]["detected"]
                sum_w.writerow([ts, eh, a, r.up, int(atks), int(det),
                                round(det / atks, 3) if atks else 0.0,
                                int(agg[a]["spike_fp"]), int(agg[a]["normal_fp"]), r.acl])
            print(f"[{datetime.now():%H:%M:%S}] {eh:.2f}h | "
                  + " | ".join(f"{a}: {int(agg[a]['detected'])}/{int(agg[a]['attacks'])} det"
                               for a in ARCHS))

        time.sleep(max(0, args.interval - (time.monotonic() - mono)))

    if not jump and phase == "attack":
        end_attack()
    elif not jump and phase == "spike":
        end_spike()
    print("\n[soak] encerrando as camadas JADE...")
    for r in runners:
        r.stop()
    epi_f.close()
    sum_f.close()
    win_fh.close()
    print(f"[soak] fim. {episode_id} episódios em {(time.monotonic()-m0)/3600:.2f} h.")
    print(f"  -> {prefix}episodes.csv, {prefix}windows.csv.gz, {prefix}summary.csv, {prefix}meta.json")
    if jump:
        sys.exit(3)
    if _stop["flag"]:
        sys.exit(4)  # interrompida antes do prazo: a fila não deve tratar como concluída


if __name__ == "__main__":
    main()
