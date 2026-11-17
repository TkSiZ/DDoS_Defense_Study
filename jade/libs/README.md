# jade/libs

`bdi4jade.jar` (BDI4JADE, de Ingrid Nunes) vem incluído porque não está no
Maven Central. Foi compilado a partir do código-fonte oficial
(<https://github.com/ingridnunes/bdi4jade>, branch `main`) contra JADE 4.3 e
commons-logging, no JDK 17. Para reconstruir:

```bash
curl -sL -o bdi4jade.zip https://github.com/ingridnunes/bdi4jade/archive/refs/heads/main.zip
python3 -c "import zipfile; zipfile.ZipFile('bdi4jade.zip').extractall('.')"
javac -cp jade-4.3.jar:commons-logging-1.2.jar -d out $(find bdi4jade-main/bdi4jade/src/main/java -name '*.java')
jar cf bdi4jade.jar -C out .
```

Licença: LGPL (ver `BDI4JADE-LICENSE`).

`jade-4.3.jar`, `json-20231013.jar` e `commons-logging-1.2.jar` são baixados
do Maven Central pelo `../build.sh` e não ficam no repositório.
