#!/bin/bash
# Sobe JADE, o controlador os-ken e o mininet_auto.py.
#   AGENT=bdi ./overnight.sh --duration 28800
# Variáveis: AGENT, PORT (7070), VENV
set -u
AGENT="${AGENT:-bdi}"
PORT="${PORT:-7070}"
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${VENV:-$HERE/../.venv}"
cd "$HERE" || exit 1

JADE_PID=""; CTRL_PID=""
cleanup() {
  echo "[overnight] encerrando..."
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID" 2>/dev/null
  [ -n "$JADE_PID" ] && kill "$JADE_PID" 2>/dev/null
  sudo mn -c >/dev/null 2>&1
  echo "[overnight] limpo. Logs: reasoning_${AGENT}.log, controller.log, attack_schedule.log"
}
trap cleanup EXIT INT TERM

if ! command -v java >/dev/null; then
  echo "ERRO: 'java' não encontrado. Instale um JDK 11+ (ver jade/README.md)."; exit 1
fi
if [ ! -d jade/classes ]; then
  echo "[overnight] compilando a camada de raciocínio (jade/build.sh)..."
  ( cd jade && ./build.sh ) || { echo "ERRO: build do JADE falhou."; exit 1; }
fi
echo "[overnight] subindo raciocínio ($AGENT) na porta $PORT..."
( cd jade && ./run.sh "$AGENT" "$PORT" ) >"reasoning_${AGENT}.log" 2>&1 &
JADE_PID=$!
sleep 6
if ! kill -0 "$JADE_PID" 2>/dev/null; then
  echo "ERRO: camada de raciocínio morreu. Veja reasoning_${AGENT}.log:"; tail -n 15 "reasoning_${AGENT}.log"; exit 1
fi

if [ ! -x "$VENV/bin/osken-manager" ]; then
  echo "ERRO: osken-manager não encontrado em $VENV/bin. Ajuste VENV."; exit 1
fi
echo "[overnight] subindo o controlador os-ken (conecta em :$PORT)..."
REASONING_PORT="$PORT" "$VENV/bin/osken-manager" ddos_controller.py >controller.log 2>&1 &
CTRL_PID=$!
sleep 4
if ! kill -0 "$CTRL_PID" 2>/dev/null; then
  echo "ERRO: controlador morreu. Veja controller.log:"; tail -n 15 controller.log; exit 1
fi

echo "[overnight] subindo a rede Mininet automática (precisa de sudo)..."
sudo python3 mininet_auto.py "$@"
echo "[overnight] orquestrador finalizado."
