"""Sobe e derruba uma instância da camada de agentes (JADE) para os experimentos."""

import glob
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
N_EDGES = 3


def _java():
    if os.environ.get("JAVA"):
        return os.environ["JAVA"]
    if os.environ.get("JAVA_HOME"):
        cand = os.path.join(os.environ["JAVA_HOME"], "bin", "java")
        if os.path.exists(cand):
            return cand
    found = shutil.which("java")
    if not found:
        sys.exit("ERRO: 'java' não encontrado. Defina JAVA=/caminho/para/java "
                 "ou instale um JDK (ver jade/README.md).")
    return found


def _classpath():
    jars = glob.glob(os.path.join(HERE, "jade", "libs", "*.jar"))
    classes = os.path.join(HERE, "jade", "classes")
    if not os.path.isdir(classes) or not jars:
        sys.exit("ERRO: camada JADE não compilada. Rode: cd jade && ./build.sh")
    return os.pathsep.join(jars + [classes])


def start_jade(arch, port, logpath, env=None, edges=N_EDGES):
    cmd = [_java(), "-cp", _classpath(), "br.uea.tcc2.agents.Launcher",
           "--agent", arch, "--edges", str(edges), "--port", str(port)]
    log = open(logpath, "w")
    full_env = dict(os.environ)
    if env:
        full_env.update({k: str(v) for k, v in env.items()})
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=full_env)
    for _ in range(120):
        time.sleep(0.25)
        if proc.poll() is not None:
            raise RuntimeError(f"JADE morreu ao iniciar. Veja {logpath}.")
        try:
            if "escutando em" in open(logpath).read():
                break
        except OSError:
            pass
    else:
        proc.terminate()
        raise RuntimeError(f"JADE não ficou pronto a tempo. Veja {logpath}.")
    time.sleep(2.0)
    return proc, log


def stop_jade(proc, log):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    log.close()
