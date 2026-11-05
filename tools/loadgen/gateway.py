"""msec_load_gateway as a controlled subprocess (stdin commands, JSON stats on stdout)."""

from __future__ import annotations

import collections
import json
import queue
import subprocess
import threading
from pathlib import Path

import keylog
from pki import EPOCH_STRIDE, Pki


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
               "--protection", p["protection"], "--accept", p.get("accept") or "-",
               "--freshness", on_off(p["freshness"]),
               "--replay", on_off(p["replay"]), "--key-binding", on_off(p["key_binding"]),
               "--rate-limit", str(p["rate_limit"]), "--persistence", s["persistence"],
               "--sending-key", str(sending_key),
               "--epoch-state", str(pki.epoch_state), "--epoch-stride", str(EPOCH_STRIDE),
               "--downlink", str(config["downlink"]["rate"]), "--zone", config["load"]["zone"],
               "--control", "stdin", "--stats", "json", "--report", "1000"]
        if verbose:
            cmd.append("--verbose")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, bufsize=1,
                                     env=keylog.preload_env(keylog.library_for(binary)))
        self.latest: dict = {}
        self.log: collections.deque[str] = collections.deque(maxlen=5000)
        self._summaries: queue.Queue = queue.Queue()
        self._connects: queue.Queue = queue.Queue()
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
            elif msg.get("type") == "connect":
                self._connects.put(msg)

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

    def apply(self, **settings) -> None:
        """Several settings at once, validated together by the gateway (a
        combination like protection=none with freshness=on is refused)."""
        if settings:
            self.send("apply " + " ".join(
                f"{k}={on_off(v) if isinstance(v, bool) else (v if v != '' else '-')}"
                for k, v in settings.items()))

    def add_key(self, line: str) -> None:
        self.send(f"key add {line}")

    def revoke_key(self, key_id: int) -> None:
        self.send(f"key revoke {key_id}")

    def reconnect(self) -> None:
        self.send("reconnect")

    def reset(self) -> None:
        self.send("reset")

    def connect_test(self, count: int = 5, timeout: float = 60) -> dict:
        """Times `count` reconnects (TCP + TLS + CONNECT + resubscribe)."""
        self.send(f"connect-test {count}")
        return self._connects.get(timeout=timeout)

    @property
    def pid(self) -> int:
        return self.proc.pid

    def summary(self, timeout: float = 30) -> dict:
        self.send("summary")
        return self._summaries.get(timeout=timeout)

    def stop(self) -> None:
        self.send("quit")
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
