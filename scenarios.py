"""
Gerador de tráfego sintético da topologia em estrela, com verdade-terra: cada
pacote leva "atk" (True no ataque), campo que o detector não lê.

Vetores vistos no projeto: volumetric, low_rate, pulsing (Kuzmanovic; Knightly,
2003) e multi. Inéditos: carpet, reflection, rotating, ramp e botnet. Picos
legítimos seguem a distinção flash crowd x DDoS de Jung; Krishnamurthy;
Rabinovich (2002): clientes reais e recorrentes, em vez de origens forjadas.
"""

import random

VICTIM_IP = "10.0.0.99"

NORMAL_PPS = (150, 300)
VOLUMETRIC_PPS = 4000
VOLUMETRIC_SOURCES = 1600
LOW_RATE_PPS = 450         # abaixo do limiar de volume
LOW_RATE_SOURCES = 1200


def _random_ip():
    return (f"{random.randint(1, 223)}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(1, 254)}")


def _domain_normal_sources(dom):
    base = 10 + dom * 40
    return [f"192.168.{dom}.{i}" for i in range(1, 51)] + \
           [f"10.{dom}.0.{i}" for i in range(base, base + 10)]


def _normal_destinations(dom):
    return [f"10.0.0.{i}" for i in range(1, 11)] + [VICTIM_IP]


def _normal(dom, n):
    srcs = _domain_normal_sources(dom)
    dsts = _normal_destinations(dom)
    return [{"src_ip": random.choice(srcs), "dst_ip": random.choice(dsts),
             "protocol": random.choice(["TCP", "UDP"])} for _ in range(n)]


def _spoofed(dom, n, n_sources):
    srcs = [_random_ip() for _ in range(n_sources)]
    return [{"src_ip": random.choice(srcs), "dst_ip": VICTIM_IP,
             "protocol": random.choice(["UDP", "ICMP"])} for _ in range(n)]


def _legit_pool(dom, size):
    size = max(1, size)
    return [f"100.{64 + (dom % 60)}.{(i >> 8) & 255}.{i & 255}"
            for i in range(size)]


VECTORS_SEEN = ["volumetric", "low_rate", "pulsing", "multi"]
VECTORS_NEW = ["carpet", "reflection", "rotating", "ramp", "botnet"]
CARPET_TARGETS = [f"10.0.1.{i}" for i in range(1, 65)]
REFLECTORS = 300
BOTNET_SIZE = 800
ROTATE_EVERY = 5
ROTATE_POOL = ["volumetric", "low_rate", "pulsing", "reflection"]
RAMP_START = 0.05
RATE_LIMIT_PPS = 100


def _tag(pkts, atk):
    for p in pkts:
        p["atk"] = atk
    return pkts


def background(dom):
    return _tag(_normal(dom, random.randint(*NORMAL_PPS)), False)


def _from_pool(pool, n, proto):
    return [{"src_ip": random.choice(pool), "dst_ip": VICTIM_IP, "protocol": proto}
            for _ in range(n)]


class AttackEpisode:
    """Um ataque na estrela: sabe o vetor (e sub-vetor) de cada janela."""

    def __init__(self, vector, alpha, n_edges, duration):
        self.vector = vector
        self.alpha = alpha
        self.n = n_edges
        self.duration = max(1, duration)
        size = lambda base: max(2 * n_edges, int(base * alpha))
        self.reflectors = [_random_ip() for _ in range(size(REFLECTORS))]
        self.bots = [_random_ip() for _ in range(size(BOTNET_SIZE))]
        self.sequence = []
        if vector == "rotating":
            prev = None
            for _ in range(self.duration // ROTATE_EVERY + 1):
                prev = random.choice([v for v in ROTATE_POOL if v != prev])
                self.sequence.append(prev)

    def targets(self):
        return set(CARPET_TARGETS) if self.vector == "carpet" else {VICTIM_IP}

    def current(self, t):
        if self.vector == "rotating":
            return self.sequence[t // ROTATE_EVERY], self.alpha
        if self.vector == "ramp":
            frac = t / max(1, self.duration - 1)
            return "volumetric", self.alpha * (RAMP_START + (1 - RAMP_START) * frac)
        return self.vector, self.alpha

    def _share(self, total, alpha):
        return max(1, int(total * alpha) // self.n)

    def edge_packets(self, d, t):
        v, a = self.current(t)
        n = self.n
        if v == "volumetric" or (v == "multi" and d % 2 == 0):
            pk = _spoofed(d, self._share(VOLUMETRIC_PPS, a), max(2, int(VOLUMETRIC_SOURCES * a) // n))
        elif v == "low_rate" or v == "multi":
            pk = _spoofed(d, self._share(LOW_RATE_PPS, a), max(2, int(LOW_RATE_SOURCES * a) // n))
        elif v == "pulsing":
            pk = (_spoofed(d, self._share(VOLUMETRIC_PPS, a), max(2, int(VOLUMETRIC_SOURCES * a) // n))
                  if t % 2 == 0 else [])
        elif v == "carpet":
            srcs = [_random_ip() for _ in range(max(2, int(VOLUMETRIC_SOURCES * a) // n))]
            pk = [{"src_ip": random.choice(srcs), "dst_ip": random.choice(CARPET_TARGETS),
                   "protocol": "UDP"} for _ in range(self._share(VOLUMETRIC_PPS, a))]
        elif v == "reflection":
            pool = self.reflectors[d::n] or self.reflectors
            pk = _from_pool(pool, self._share(VOLUMETRIC_PPS, a), "UDP")
        elif v == "botnet":
            pool = self.bots[d::n] or self.bots
            pk = _from_pool(pool, self._share(VOLUMETRIC_PPS, a), "TCP")
        else:
            raise ValueError(f"vetor desconhecido: {v}")
        return _tag(pk, True)


class FlashCrowd:
    """Pico legítimo sustentado: clientes reais e recorrentes convergindo na vítima."""

    def __init__(self, alpha, n_edges):
        users = max(2 * n_edges, int(VOLUMETRIC_SOURCES * alpha))
        self.pools = [_legit_pool(d, max(1, users // n_edges)) for d in range(n_edges)]
        self.pps = max(n_edges, int(VOLUMETRIC_PPS * alpha))
        self.n = n_edges

    def edge_packets(self, d):
        return _tag(_from_pool(self.pools[d], max(1, self.pps // self.n), "TCP"), False)


def apply_mitigation(pkts, rules, cap=RATE_LIMIT_PPS, rng=random):
    """O que sai de um switch com as regras {alvo: estratégia}: drop descarta,
    rate_limit deixa passar até cap pacotes por alvo, scrubbing remove só o ataque."""
    if not rules:
        return pkts
    pkts = list(pkts)
    rng.shuffle(pkts)
    out, passed = [], {}
    for p in pkts:
        s = rules.get(p["dst_ip"])
        if s is None:
            out.append(p)
        elif s == "scrubbing":
            if not p["atk"]:
                out.append(p)
        elif s == "rate_limit":
            if passed.get(p["dst_ip"], 0) < cap:
                passed[p["dst_ip"]] = passed.get(p["dst_ip"], 0) + 1
                out.append(p)
    return out
