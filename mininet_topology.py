#!/usr/bin/env python3
"""
Topologia em estrela: N switches de borda (e1..eN), por onde entra o tráfego,
ligados a um switch central (c) junto da vítima. Um agente por switch.

          legit atk     legit atk     legit atk
              \ /           \ /           \ /
              e1            e2            e3
                 \          |          /
                  +------- c (central) -------+-- victim(10.0.0.99)

Suba os agentes e o controlador antes:
    cd jade && ./run.sh hybrid 7070 3
    EDGES=3 REASONING_PORT=7070 osken-manager ddos_controller.py
    sudo python3 mininet_topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

VICTIM_IP = '10.0.0.99'


def build_topology(n_edges=3, n_legit_per=2, n_attackers_per=2, extra_servers=()):
    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    # dpid 1..N = bordas (domínios 0..N-1); dpid N+1 = central (domínio N)
    edges = [net.addSwitch(f'e{i}', protocols='OpenFlow13', dpid=f'{i:016x}')
             for i in range(1, n_edges + 1)]
    center = net.addSwitch('c', protocols='OpenFlow13', dpid=f'{n_edges + 1:016x}')
    for e in edges:
        net.addLink(e, center)
    switches = edges

    victim = net.addHost('victim', ip=f'{VICTIM_IP}/24')
    net.addLink(victim, center)
    # outros servidores legítimos junto do central (destinos do tráfego normal)
    servers = []
    for i, ip in enumerate(extra_servers, start=1):
        s = net.addHost(f'srv{i}', ip=f'{ip}/24')
        net.addLink(s, center)
        servers.append(s)

    legit_hosts, attacker_hosts = [], []
    host_ip = 10
    for si, s in enumerate(switches, start=1):
        for j in range(1, n_legit_per + 1):
            h = net.addHost(f'legit{si}_{j}', ip=f'10.0.0.{host_ip}/24')
            net.addLink(h, s)
            legit_hosts.append(h)
            host_ip += 1
    host_ip = 150
    for si, s in enumerate(switches, start=1):
        for j in range(1, n_attackers_per + 1):
            h = net.addHost(f'atk{si}_{j}', ip=f'10.0.0.{host_ip}/24')
            net.addLink(h, s)
            attacker_hosts.append(h)
            host_ip += 1

    net.start()
    if extra_servers:
        return net, victim, legit_hosts, attacker_hosts, servers
    return net, victim, legit_hosts, attacker_hosts


if __name__ == '__main__':
    setLogLevel('info')
    net, victim, legit_hosts, attacker_hosts = build_topology()

    print("\nTopologia em estrela pronta.")
    print(f"  Vítima:     {victim.name} ({victim.IP()})")
    print(f"  Legítimos:  {[h.name for h in legit_hosts]}")
    print(f"  Atacantes:  {[h.name for h in attacker_hosts]}")
    print("\nPasso a passo dentro do CLI do Mininet:")
    print("  1) victim python3 -m http.server 80 &")
    print("  2) tráfego legítimo (deixe rodar ~10s p/ calibrar a baseline):")
    print("     legit1_1 bash -c 'while true; do curl -s 10.0.0.99 -o /dev/null; sleep 0.5; done' &")
    print("     legit2_1 bash -c 'while true; do curl -s 10.0.0.99 -o /dev/null; sleep 0.6; done' &")
    print("  3) ataque distribuído (de vários switches ao mesmo tempo):")
    print("     atk1_1 timeout 12 hping3 --flood --rand-source -p 80 -S 10.0.0.99 &")
    print("     atk2_1 timeout 12 hping3 --flood --rand-source -p 80 -S 10.0.0.99 &")
    print("     atk3_1 timeout 12 hping3 --flood --rand-source -p 80 -S 10.0.0.99 &")
    print("  O log do controlador mostra '*** MITIGAÇÃO' quando um agente decide mitigar.\n")

    CLI(net)
    net.stop()
