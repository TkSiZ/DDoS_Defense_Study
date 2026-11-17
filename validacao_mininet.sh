#!/bin/bash
# Validação no Mininet das três arquiteturas (~6 min cada). Rode com: sudo ./validacao_mininet.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
U="${SUDO_USER:?rode com sudo}"
PORT=7170
cd "$HERE" || exit 1

for arch in ${@:-eca bdi hybrid}; do
  D="$HERE/validacao/$arch"
  rm -rf "$D"; sudo -u "$U" mkdir -p "$D"
  mn -c > /dev/null 2>&1
  echo "=== $arch"
  sudo -u "$U" jade/run.sh "$arch" "$PORT" 3 > "$D/agentes.log" 2>&1 &
  for i in $(seq 60); do grep -q "escutando" "$D/agentes.log" && break; sleep 1; done
  grep -q "escutando" "$D/agentes.log" || { echo "agentes não subiram: $D/agentes.log"; exit 1; }
  sleep 3
  (cd "$D" && sudo -u "$U" env EDGES=3 REASONING_PORT=$PORT SERVERS=10.0.0.97,10.0.0.98,10.0.0.99 osken-manager "$HERE/ddos_controller.py" > controlador.log 2>&1) &
  sleep 4
  python3 validacao_mininet.py --out "$D" --ctl-dir "$D"
  pkill -f "ddos_controller.py"
  pkill -f "Launcher --agent $arch --port $PORT"
  sleep 2
  chown -R "$U": "$D"
done
mn -c > /dev/null 2>&1
echo "fim: resultados em $HERE/validacao/"
