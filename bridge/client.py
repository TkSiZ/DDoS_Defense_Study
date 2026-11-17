"""
Cliente da ponte com a camada de agentes, usado pelo soak e pelo controlador.
Timeout curto no socket para não travar o laço do os-ken (eventlet). Protocolo
em PROTOCOL.md.
"""

import json
import socket
import time


class ReasoningClient:
    def __init__(self, host="127.0.0.1", port=7070):
        self.host = host
        self.port = port
        self.sock = None
        self.buf = b""

    def connect(self, timeout=5.0):
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(0.3)
        return self

    def _send(self, obj):
        self.sock.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())

    def reset(self, run):
        self._send({"type": "reset", "run": run})

    def send_features(self, tick, domain, f):
        self._send({"type": "features", "tick": tick, "domain": domain, "f": f})

    def kill_agent(self, domain):
        self._send({"type": "kill", "domain": domain})

    def spawn_agent(self, domain):
        self._send({"type": "spawn", "domain": domain})

    def switch_state(self, domain, targets):
        """Regras instaladas num switch, enviadas a quem assumiu aquele domínio."""
        self._send({"type": "switch_state", "domain": domain, "targets": list(targets)})

    def drain(self, max_wait=0.3):
        """Lê todos os quadros (decision e telemetry) por até max_wait s."""
        out = []
        self.sock.settimeout(max_wait)
        end = time.time() + max_wait
        while time.time() < end:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
            except socket.timeout:
                break
            self._parse(out)
        self._parse(out)   # consome linhas completas já no buffer
        return out

    def _parse(self, out):
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line.decode())
            msg["_rx_ms"] = time.time() * 1000
            out.append(msg)

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
