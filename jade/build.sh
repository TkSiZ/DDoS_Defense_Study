#!/bin/bash
# Compila os agentes sem Maven. O bdi4jade.jar já vem em libs/ (não está no
# Maven Central, ver libs/README.md).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
mkdir -p libs classes

fetch() { [ -f "libs/$1" ] || { echo "baixando $1..."; curl -sL -o "libs/$1" "$2"; }; }
fetch jade-4.3.jar          "https://repo1.maven.org/maven2/net/sf/ingenias/jade/4.3/jade-4.3.jar"
fetch json-20231013.jar     "https://repo1.maven.org/maven2/org/json/json/20231013/json-20231013.jar"
fetch commons-logging-1.2.jar "https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"

CP="libs/jade-4.3.jar:libs/json-20231013.jar:libs/bdi4jade.jar:libs/commons-logging-1.2.jar"
echo "compilando..."
javac -cp "$CP" -d classes src/main/java/br/uea/tcc2/agents/*.java
echo "OK -> classes/ (use ./run.sh eca|bdi [porta])"
