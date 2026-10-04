"""A private Mosquitto whose security features can be switched while it runs.

    transport  plain | tls | mtls   one listener on one port; changing it restarts
                                    the broker (listeners can't be reloaded), and
                                    every client reconnects with the new transport
    auth       on | off             password_file + allow_anonymous, hot-reloaded
                                    with SIGHUP; Mosquitto then drops connected
                                    clients whose credentials no longer pass
    acl        on | off             acl_file, hot-reloaded with SIGHUP; applies to
                                    the next message, no reconnect

Only the active transport's listener exists, as in a real deployment: turning
TLS on means plaintext connections are no longer possible at all. With mtls
the certificate CN becomes the username (use_identity_as_username), so the
certificate replaces the password.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from pki import Pki

# open/#        every client may read and write
# restricted/   each sensor may only write its own subtree, only "gateway" reads.
# Rules match the MQTT username (%u): the claimed name without auth, the
# verified name with passwords, the certificate CN with mtls.
ACL_ZONES = """\
pattern readwrite open/#
pattern write restricted/sensors/%u/#

user gateway
topic read restricted/sensors/#
"""
ACL_OPEN = "pattern readwrite #\n"


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


class Broker:
    def __init__(self, workdir: Path, pki: Pki, host: str, port: int) -> None:
        self.workdir = workdir / "broker"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.pki = pki
        self.host = host
        self.port = port
        self.transport = "plain"
        self.auth = False
        self.acl = True
        self.proc: subprocess.Popen | None = None
        self._log = open(self.workdir / "mosquitto.log", "ab")  # noqa: SIM115

    @property
    def conf(self) -> Path:
        return self.workdir / "mosquitto.conf"

    @property
    def acl_file(self) -> Path:
        return self.workdir / "acl"

    def _write(self) -> None:
        self.acl_file.touch(mode=0o600, exist_ok=True)
        self.acl_file.write_text(ACL_ZONES if self.acl else ACL_OPEN)
        lines = [
            "per_listener_settings false",
            "persistence false",
            "log_dest stderr",
            "log_type error",
            # Large enough that a slow gateway shows up as latency, not loss.
            "max_queued_messages 100000",
            # Without it, Nagle + delayed ACKs intermittently add 14-30 ms to every
            # message once a second subscriber (e.g. the attacker) is connected.
            "set_tcp_nodelay true",
            f"allow_anonymous {'false' if self.auth else 'true'}",
            f"acl_file {self.acl_file}",
        ]
        if self.auth:
            lines.append(f"password_file {self.pki.passwd}")
        lines.append(f"listener {self.port} {self.host}")
        if self.transport in ("tls", "mtls"):
            lines += [f"cafile {self.pki.ca}", f"certfile {self.pki.server_cert}",
                      f"keyfile {self.pki.server_key}", "tls_version tlsv1.2"]
        if self.transport == "mtls":
            lines += ["require_certificate true", "use_identity_as_username true"]
        self.conf.write_text("\n".join(lines) + "\n")

    @property
    def probe_host(self) -> str:
        return "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host

    def start(self, transport: str, auth: bool, acl: bool) -> None:
        if port_open(self.probe_host, self.port):
            raise RuntimeError(f"{self.host}:{self.port} is already in use; pick another port")
        self.transport, self.auth, self.acl = transport, auth, acl
        self._write()
        self.proc = subprocess.Popen(["mosquitto", "-c", str(self.conf)],
                                     stdout=self._log, stderr=self._log)
        deadline = time.monotonic() + 5
        while not port_open(self.probe_host, self.port):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"mosquitto failed to start, see {self.workdir}/mosquitto.log")
            time.sleep(0.02)

    def reload(self, auth: bool, acl: bool) -> None:
        """ACL and authentication changes, applied without restarting."""
        self.auth, self.acl = auth, acl
        self._write()
        os.kill(self.proc.pid, signal.SIGHUP)

    def restart(self, transport: str) -> None:
        self.stop()
        self.start(transport, self.auth, self.acl)

    def stop(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def cpu_seconds(self) -> float:
        """utime + stime of the broker process, from /proc (Linux)."""
        try:
            with open(f"/proc/{self.proc.pid}/stat", encoding="ascii") as f:
                fields = f.read().rsplit(")", 1)[1].split()
        except (OSError, AttributeError):
            return 0.0
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
