#!/bin/bash
# Plano experimental (congelado antes da R1). Cada linha é uma rodada do soak;
# rode uma por vez:  ./experimentos.sh r1   (ou: ./experimentos.sh todas)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PY:-$HERE/../.venv/bin/python}"
cd "$HERE" || exit 1

run() {   # tag horas [VAR=valor ...] -- [opções do soak]
  local tag=$1 hours=$2; shift 2
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  echo "=== $tag ($hours h) ${envs[*]} $*"
  env "${envs[@]}" "$PY" soak_24h.py --tag "$tag" --hours "$hours" "$@"
}

case "${1:-}" in
  piloto) run piloto 1  -- --seed 0 ;;
  # verificação de reprodutibilidade: duas execuções com a mesma semente e falha em todo ataque
  teste1|teste2) run "$1" 0.17 -- --seed 99 --fault-prob 1.0 ;;
  # rodadas principais (24 h)
  r1)   run r1 24 -- --seed 1 ;;
  r2)   run r2 24 -- --seed 2 ;;
  r3)   run r3 24 -- --seed 3 --edges 6 ;;
  r4)   run r4 24 -- --seed 4 --fault-prob 0.6 ;;
  # ablação da comunicação
  abl)  run abl 4 -- --seed 11 --comms off ;;
  # pontos de operação para a curva ROC (limiar do ECA e confirmação do BDI)
  roc1) run roc1 3 ZSCORE_THRESHOLD=25  BDI_GOAL=0.5  -- --seed 21 ;;
  roc2) run roc2 3 ZSCORE_THRESHOLD=75  BDI_GOAL=0.9  -- --seed 22 ;;
  roc3) run roc3 3 ZSCORE_THRESHOLD=100 BDI_GOAL=0.95 -- --seed 23 ;;
  # sensibilidade (um parâmetro por vez em relação à base)
  s_decay06) run s_decay06 2 BDI_DECAY=0.6 -- --seed 31 ;;
  s_decay08) run s_decay08 2 BDI_DECAY=0.8 -- --seed 32 ;;
  s_peer0)   run s_peer0   2 BDI_PEER=0   -- --seed 33 ;;
  s_peer06)  run s_peer06  2 BDI_PEER=0.6 -- --seed 34 ;;
  s_ppsk12)  run s_ppsk12  2 PPS_K=12     -- --seed 35 ;;
  s_ppsk24)  run s_ppsk24  2 PPS_K=24     -- --seed 36 ;;
  todas)
    for t in r1 r2 r3 r4 abl roc1 roc2 roc3 s_decay06 s_decay08 s_peer0 s_peer06 s_ppsk12 s_ppsk24; do
      "$0" "$t"
    done ;;
  *) echo "uso: $0 piloto|r1|r2|r3|r4|abl|roc1..3|s_*|todas"; exit 1 ;;
esac
