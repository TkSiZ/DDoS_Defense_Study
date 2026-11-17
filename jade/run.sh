#!/bin/bash
# Uso: ./run.sh eca|bdi|hybrid [porta] [nº de bordas]
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
AGENT="${1:-bdi}"
PORT="${2:-7070}"
EDGES="${3:-3}"
CP="libs/jade-4.3.jar:libs/json-20231013.jar:libs/bdi4jade.jar:libs/commons-logging-1.2.jar:classes"
exec java -cp "$CP" br.uea.tcc2.agents.Launcher \
  --agent "$AGENT" --port "$PORT" --edges "$EDGES"
