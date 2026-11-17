#!/usr/bin/env python3
"""
Sobe a topologia Mininet e alterna fases normais e de ataque (hping3
--rand-source) sem intervenção, registrando os ataques em attack_schedule.log.
Suba o controlador antes. Usa o python do sistema e precisa de root.

    sudo python3 mininet_auto.py --duration 28800
    sudo python3 mininet_auto.py --duration 3600 --attack-sec 20 --normal-sec 40
"""

import argparse
import random
import signal
import time
from datetime import datetime

from mininet.log import setLogLevel

from mininet_topology import build_topology, VICTIM_IP

LOG = "attack_schedule.log"
_running = {"flag": True}


def _log(msg):
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


def _stop(signum, frame):
    _log("sinal recebido -> encerrando após a fase atual")
    _running["flag"] = False


def main():
    ap = argparse.ArgumentParser(description="Orquestrador automático do Mininet.")
    ap.add_argument("--duration", type=int, default=28800, help="duração total (s)")
    ap.add_argument("--edges", "--switches", type=int, default=3)
    ap.add_argument("--legit-per", type=int, default=2)
    ap.add_argument("--attackers-per", type=int, default=2)
    ap.add_argument("--attack-sec", type=int, default=15, help="duração de cada ataque (s)")
    ap.add_argument("--normal-sec", type=int, default=45, help="intervalo normal entre ataques (s)")
    ap.add_argument("--jitter", type=float, default=0.4,
                    help="variação aleatória (+/-) aplicada às durações")
    ap.add_argument("--warmup", type=int, default=20,
                    help="segundos de tráfego normal antes do 1º ataque (calibração)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    setLogLevel("warning")

    net, victim, legit_hosts, attacker_hosts = build_topology(
        n_edges=args.edges, n_legit_per=args.legit_per,
        n_attackers_per=args.attackers_per)

    procs = []
    try:
        _log(f"rede no ar: vítima={victim.IP()} legit={len(legit_hosts)} "
             f"atk={len(attacker_hosts)}")

        victim.cmd("pkill -f 'http.server' 2>/dev/null")
        procs.append(victim.popen("python3 -m http.server 80",
                                  shell=True))

        # tráfego legítimo
        for h in legit_hosts:
            delay = round(random.uniform(0.4, 0.9), 2)
            cmd = (f"while true; do curl -s --max-time 2 {VICTIM_IP} "
                   f"-o /dev/null; sleep {delay}; done")
            procs.append(h.popen(cmd, shell=True))
        _log(f"tráfego legítimo iniciado; warmup de {args.warmup}s (calibração)")
        time.sleep(args.warmup)

        t_end = time.time() + args.duration
        cycle = 0
        while _running["flag"] and time.time() < t_end:
            cycle += 1
            atk_dur = max(5, int(args.attack_sec * random.uniform(1 - args.jitter,
                                                                  1 + args.jitter)))
            k = random.randint(1, len(attacker_hosts))
            attackers = random.sample(attacker_hosts, k)
            names = ",".join(h.name for h in attackers)
            _log(f"CICLO {cycle}: ATAQUE início | {k} atacantes [{names}] | {atk_dur}s")

            atk_procs = []
            for h in attackers:
                cmd = (f"timeout {atk_dur} hping3 --flood --rand-source "
                       f"-p 80 -S {VICTIM_IP}")
                atk_procs.append(h.popen(cmd, shell=True))
            time.sleep(atk_dur + 2)
            for p in atk_procs:
                try:
                    p.terminate()
                except Exception:
                    pass
            _log(f"CICLO {cycle}: ATAQUE fim")

            if not _running["flag"] or time.time() >= t_end:
                break
            normal_dur = max(5, int(args.normal_sec * random.uniform(1 - args.jitter,
                                                                     1 + args.jitter)))
            _log(f"CICLO {cycle}: fase NORMAL | {normal_dur}s")
            # dorme em fatias para reagir ao Ctrl-C
            slept = 0
            while slept < normal_dur and _running["flag"] and time.time() < t_end:
                time.sleep(min(2, normal_dur - slept))
                slept += 2

        _log(f"concluído: {cycle} ciclos de ataque executados")
    finally:
        _log("parando processos e derrubando a rede...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for h in legit_hosts + attacker_hosts + [victim]:
            try:
                h.cmd("kill %while 2>/dev/null; pkill -P $$ 2>/dev/null")
            except Exception:
                pass
        net.stop()
        _log("rede parada.")


if __name__ == "__main__":
    main()
