"""
Medidas de detecção calculadas a cada janela, iguais para ECA e BDI:

  1. volume (pps)                     - Najafimehr et al., 2023
  2. entropia de IP origem/destino    - Feinstein et al., 2003
  3. fan-in (origens por destino)     - Mirkovic; Reiher, 2004
  4. z-score do fan-in vs. baseline   - Majed et al., 2020

O soak entrega pacotes; o controlador os-ken entrega flow-stats.
"""

import math
import os
import statistics
from collections import Counter, defaultdict


def _envf(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


PPS_THRESHOLD = _envf("PPS_THRESHOLD", 1000)   # usado só sem baseline de volume
# limiar de volume relativo: média + K desvios do volume normal da posição;
# K = 18 reproduz ~1000 pps numa borda com tráfego normal de 150-300 pps
PPS_K = _envf("PPS_K", 18)
SRC_ENTROPY_RISE_THRESHOLD = _envf("SRC_ENTROPY_RISE", 0.5)
DST_ENTROPY_DROP_THRESHOLD = _envf("DST_ENTROPY_DROP", 0.5)
# calibrado empiricamente: flash crowd dá z ~ 14, ataque dá z > 300
ZSCORE_THRESHOLD = _envf("ZSCORE_THRESHOLD", 50)


def entropy(counts):
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


class Baseline:
    def __init__(self):
        self.src_entropy_hist = []
        self.dst_entropy_hist = []
        self.fanin_hist = defaultdict(list)
        self.pps_hist = []

    def calibrate(self, src_entropy, dst_entropy, fanin_per_dst, pps=None):
        if pps is not None:
            self.pps_hist.append(pps)
        self.src_entropy_hist.append(src_entropy)
        self.dst_entropy_hist.append(dst_entropy)
        for dst, n in fanin_per_dst.items():
            self.fanin_hist[dst].append(n)

    def zscore_fanin(self, dst, current_fanin):
        hist = self.fanin_hist.get(dst, [])
        if len(hist) < 2:
            return 0.0
        mean = statistics.mean(hist)
        std = statistics.pstdev(hist) or 1e-6
        return (current_fanin - mean) / std

    def pps_threshold(self):
        if len(self.pps_hist) < 2:
            return PPS_THRESHOLD
        return statistics.mean(self.pps_hist) + PPS_K * max(statistics.pstdev(self.pps_hist), 1.0)

    @property
    def mean_src_entropy(self):
        return statistics.mean(self.src_entropy_hist) if self.src_entropy_hist else 0.0

    @property
    def mean_dst_entropy(self):
        return statistics.mean(self.dst_entropy_hist) if self.dst_entropy_hist else 0.0


def _counts_from_packets(packets):
    src, dst, fanin = Counter(), Counter(), defaultdict(set)
    for p in packets:
        src[p["src_ip"]] += 1
        dst[p["dst_ip"]] += 1
        fanin[p["dst_ip"]].add(p["src_ip"])
    return len(packets), src, dst, {d: len(s) for d, s in fanin.items()}


def _counts_from_flows(records):
    """records: [{"src_ip", "dst_ip", "packet_count"}, ...]"""
    src, dst, fanin = Counter(), Counter(), defaultdict(set)
    for r in records:
        src[r["src_ip"]] += r["packet_count"]
        dst[r["dst_ip"]] += r["packet_count"]
        fanin[r["dst_ip"]].add(r["src_ip"])
    pps = sum(r["packet_count"] for r in records)
    return pps, src, dst, {d: len(s) for d, s in fanin.items()}


def _calibrate(baseline, pps, src, dst, fanin):
    baseline.calibrate(entropy(src), entropy(dst), fanin, pps)


def compute_signals(pps, src_counts, dst_counts, fanin_per_dst, baseline):
    """Calcula todas as medidas, sem parar no corte de volume: o ECA usa só
    "threat" (todas as condições juntas); o BDI acumula as medidas parciais."""
    src_entropy = entropy(src_counts)
    dst_entropy = entropy(dst_counts)
    src_rise = src_entropy - baseline.mean_src_entropy
    dst_drop = baseline.mean_dst_entropy - dst_entropy

    target_ip, fanin, zscore = None, 0, 0.0
    if fanin_per_dst:
        target_ip = max(fanin_per_dst, key=fanin_per_dst.get)
        fanin = fanin_per_dst[target_ip]
        zscore = round(baseline.zscore_fanin(target_ip, fanin), 2)

    over_usage = pps > baseline.pps_threshold()
    anomalous_usage = (src_rise > SRC_ENTROPY_RISE_THRESHOLD
                       and dst_drop > DST_ENTROPY_DROP_THRESHOLD)

    return {
        "pps": pps,
        "src_entropy": round(src_entropy, 3),
        "dst_entropy": round(dst_entropy, 3),
        "src_rise": round(src_rise, 3),
        "dst_drop": round(dst_drop, 3),
        "over_usage": over_usage,
        "anomalous_usage": anomalous_usage,
        "fanin": fanin,
        "zscore": zscore,
        "target_ip": target_ip,
        "threat": over_usage and anomalous_usage and zscore > ZSCORE_THRESHOLD,
    }


def calibrate_from_packets(baseline, packets):
    _calibrate(baseline, *_counts_from_packets(packets))


def calibrate_from_flow_stats(baseline, records):
    _calibrate(baseline, *_counts_from_flows(records))


def features_from_packets(packets, baseline):
    return compute_signals(*_counts_from_packets(packets), baseline)


def features_from_flow_stats(records, baseline):
    return compute_signals(*_counts_from_flows(records), baseline)
