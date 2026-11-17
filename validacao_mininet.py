#!/usr/bin/env python3
"""
Validação de ponta a ponta no Mininet (uma arquitetura por execução): tráfego
legítimo HTTP para a vítima e para dois outros servidores, ataques com hping3 e,
no fim, a queda de um agente de borda durante um ataque. Registra os ataques, as
respostas HTTP e as regras de mitigação (prioridade 100) presentes em cada switch.

Chamado por validacao_mininet.sh, que sobe os agentes e o controlador antes.
    sudo python3 validacao_mininet.py --out validacao/hybrid --ctl-dir validacao/hybrid
"""

import argparse
import os
import random
import subprocess
import threading
import time

from mininet.log import setLogLevel

from mininet_topology import build_topology, VICTIM_IP

OUTROS = ("10.0.0.98", "10.0.0.97")
# backlog grande: com o padrão (5), SYNs forjados que passam pela limitação de taxa
# enchem a fila da vítima e o tráfego legítimo não volta entre um ataque e outro
SERVIDOR = ("python3 -c 'import http.server as h; h.ThreadingHTTPServer.request_queue_size = 1024; "
            "h.ThreadingHTTPServer((\"\", 80), h.SimpleHTTPRequestHandler).serve_forever()'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--ctl-dir", required=True, help="diretório de trabalho do controlador")
    ap.add_argument("--ciclos", type=int, default=6)
    ap.add_argument("--attack-sec", type=int, default=20)
    ap.add_argument("--normal-sec", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=25)
    ap.add_argument("--seed", type=int, default=7)
    # taxa por atacante ao alcance de um controlador em Python: cada pacote de origem
    # aleatória vira PACKET_IN na borda e no central
    ap.add_argument("--pps", type=int, default=300)
    args = ap.parse_args()
    random.seed(args.seed)
    os.makedirs(args.out, exist_ok=True)
    setLogLevel("warning")

    net, victim, legit, atk, srvs = build_topology(n_edges=3, extra_servers=OUTROS)
    sws = [s.name for s in net.switches]
    procs, fim = [], threading.Event()
    sched = open(f"{args.out}/ataques.csv", "w", buffering=1)
    sched.write("ciclo,inicio,fim,atacantes,falha\n")

    def flows():
        with open(f"{args.out}/regras.csv", "w", buffering=1) as fh:
            fh.write("t,switch,tabela,pacotes,acoes\n")
            while not fim.is_set():
                t = time.time()
                for s in sws:
                    r = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", s],
                                       capture_output=True, text=True)
                    if r.returncode:
                        fh.write(f"{t:.3f},{s},ERRO {r.stderr.strip()}\n")
                    for ln in r.stdout.splitlines():
                        if "priority=100" in ln:
                            tab = ln.split("table=")[1].split(",")[0]
                            pk = ln.split("n_packets=")[1].split(",")[0]
                            fh.write(f"{t:.3f},{s},{tab},{pk},{ln.split('actions=')[-1].strip()}\n")
                fim.wait(0.5)

    try:
        for s in [victim] + srvs:
            procs.append(s.popen(SERVIDOR, shell=True))
        destinos = " ".join((VICTIM_IP,) + OUTROS)
        for h in legit:
            cmd = (f"while true; do for d in {destinos}; do echo $(date +%s.%N) $d $(curl -s -o /dev/null "
                   f"-w '%{{http_code}}' --max-time 2 $d); sleep 0.5; done; done > {args.out}/legit_{h.name}.log")
            procs.append(h.popen(cmd, shell=True))
        threading.Thread(target=flows, daemon=True).start()
        time.sleep(args.warmup)

        for c in range(1, args.ciclos + 1):
            falha = c == args.ciclos
            if falha:
                # o agente da borda e1 cai antes do ataque, que passa obrigatoriamente por e1
                with open(f"{args.ctl_dir}/falha.cmd", "w") as fh:
                    fh.write("kill 0")
                time.sleep(5)
                quem = [h for h in atk if h.name.startswith("atk1_")]
            else:
                quem = random.sample(atk, random.randint(1, len(atk)))
            t0 = time.time()
            ps = [h.popen(f"timeout {args.attack_sec} hping3 -i u{1000000 // args.pps} --rand-source -p 80 -S {VICTIM_IP}",
                          shell=True) for h in quem]
            time.sleep(args.attack_sec + 1)
            for p in ps:
                p.terminate()
            # o timeout encerra o hping3 em t0 + attack_sec
            sched.write(f"{c},{t0:.3f},{t0 + args.attack_sec:.3f},{'|'.join(h.name for h in quem)},{int(falha)}\n")
            print(f"ciclo {c}: {len(quem)} atacantes{' (borda e1 sem agente)' if falha else ''}", flush=True)
            if falha:
                with open(f"{args.ctl_dir}/falha.cmd", "w") as fh:
                    fh.write("spawn 0")
            time.sleep(args.normal_sec)
    finally:
        fim.set()
        for p in procs:
            p.terminate()
        for h in legit + atk + [victim] + srvs:
            h.cmd("pkill -f 'curl|hping3|http.server' 2>/dev/null")
        net.stop()


if __name__ == "__main__":
    main()
