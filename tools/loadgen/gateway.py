"""msec_load_gateway as a controlled subprocess (stdin commands, JSON stats on stdout)."""

from __future__ import annotations

import collections
import json
import queue
import subprocess
import threading
from pathlib import Path

from pki import Pki


def on_off(value: bool) -> str:
    return "on" if value else "off"


class GatewayProcess:
    def __init__(self, binary: Path, pki: Pki, host: str, port: int, config: dict,
                 verbose: bool = False, sending_key: int = 0) -> None:
        if not binary.exists():
            raise RuntimeError(f"{binary} not found; build it with: "
                               "cmake --preset bench && cmake --build --preset bench")
        t, p, s = config["transport"], config["payload"], config["storage"]
        cmd = [str(binary),
               "--host", host, "--port", str(port), "--tls-port", str(port),
               "--mtls-port", str(port), "--transport", t["mode"],
               "--protocol", str(t["protocol"]), "--qos", str(config["load"]["qos"]),
               "--ca", str(pki.ca), "--cert", str(pki.client_cert("gateway")),
               "--key", str(pki.client_key("gateway")),
               "--username", "gateway", "--credentials", str(pki.credentials),
               "--keys", str(pki.keys),
               "--protection", p["protection"], "--freshness", on_off(p["freshness"]),
               "--replay", on_off(p["replay"]), "--key-binding", on_off(p["key_binding"]),
               "--rate-limit", str(p["rate_limit"]), "--persistence", s["persistence"],
               "--sending-key", str(sending_key),
               "--downlink", str(config["downlink"]["rate"]), "--zone", config["load"]["zone"],
               "--control", "stdin", "--stats", "json", "--report", "1000"]
        if verbose:
            cmd.append("--verbose")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, bufsize=1)
        self.latest: dict = {}
        self.log: collections.deque[str] = collections.deque(maxlen=5000)
        self._summaries: queue.Queue = queue.Queue()
        self._ready = threading.Event()
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        if not self._ready.wait(10):
            self.proc.kill()
            raise RuntimeError("gateway did not start:\n" + "".join(self.log))

    def _read_stdout(self) -> None:
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("type") == "stats":
                self.latest = msg
            elif msg.get("type") == "summary":
                self._summaries.put(msg)

    def _read_stderr(self) -> None:
        for line in self.proc.stderr:
            self.log.append(line)
            if line.startswith("READY"):
                self._ready.set()

    def send(self, line: str) -> None:
        if self.proc.poll() is None:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()

    def set(self, key: str, value) -> None:
        self.send(f"set {key} {on_off(value) if isinstance(value, bool) else value}")

    def add_key(self, line: str) -> None:
        self.send(f"key add {line}")

    def revoke_key(self, key_id: int) -> None:
        self.send(f"key revoke {key_id}")

    def reconnect(self) -> None:
        self.send("reconnect")

    def reset(self) -> None:
        self.send("reset")

    def summary(self, timeout: float = 10) -> dict:
        self.send("summary")
        return self._summaries.get(timeout=timeout)

    def stop(self) -> None:
        self.send("quit")
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
