"""A private Mosquitto whose security features can be switched while it runs.

    mode              plain | tls | mtls   one listener; changing it restarts the broker
    tls_version       1.2 | 1.3            restart
    auth              on | off             password_file + allow_anonymous, SIGHUP reload;
                                           Mosquitto drops clients that no longer pass
    acl               on | off             acl_file, SIGHUP reload, next message. Off means
                                           no ACL at all: everything, $SYS included, is open
    clientid_binding  on | off             use_username_as_clientid: the client id is the
                                           (verified) username, so nobody can take over
                                           another client's session; restart
    sys_topics        on | off             $SYS/# broker statistics, SIGHUP reload
    max_packet        bytes, 0 = no limit  max_packet_size; restart
    max_connections   0 = no limit         restart
    revoked           usernames            removed from the password file (reload) and,
                                           with mtls, their certificates go on the CRL
                                           (restart, so established sessions end too)

Which changes need a restart was measured with Mosquitto 2.0.18: listener
options, use_username_as_clientid and max_packet_size are not re-read on
SIGHUP. Only the active transport's listener exists, as in a real deployment:
turning TLS on means plaintext connections are no longer possible at all. With
mtls the certificate CN becomes the username (use_identity_as_username).
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from pki import Pki

# open/        every client may read and write
# restricted/  each sensor may only write its own subtree and read its own
#              command topic; only "gateway" reads sensors and sends commands.
# Rules match the MQTT username (%u): the claimed name without auth, the
# verified name with passwords, the certificate CN with mtls.
ACL_ZONES = """\
pattern readwrite open/#
pattern write restricted/sensors/%u/#
pattern read restricted/actuators/%u/#

user gateway
topic read restricted/sensors/#
topic write restricted/actuators/#
"""

RESTART_KEYS = ("mode", "tls_version", "clientid_binding", "max_packet", "max_connections")
RELOAD_KEYS = ("auth", "acl", "sys_topics")
DEFAULT_SETTINGS = {"mode": "plain", "tls_version": "1.2", "auth": False, "acl": True,
                    "clientid_binding": False, "sys_topics": False, "max_packet": 0,
                    "max_connections": 0, "revoked": frozenset()}


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
        self.settings = dict(DEFAULT_SETTINGS)
        self.proc: subprocess.Popen | None = None
        self._log = open(self.workdir / "mosquitto.log", "ab")  # noqa: SIM115

    @property
    def conf(self) -> Path:
        return self.workdir / "mosquitto.conf"

    @property
    def acl_file(self) -> Path:
        return self.workdir / "acl"

    # Kept for callers that read them directly.
    @property
    def transport(self) -> str:
        return self.settings["mode"]

    def _write(self) -> None:
        s = self.settings
        self.acl_file.touch(mode=0o600, exist_ok=True)
        self.acl_file.write_text(ACL_ZONES)
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
            f"sys_interval {10 if s['sys_topics'] else 0}",
            f"allow_anonymous {'false' if s['auth'] else 'true'}",
        ]
        if s["max_packet"]:
            lines.append(f"max_packet_size {s['max_packet']}")
        if s["acl"]:
            lines.append(f"acl_file {self.acl_file}")
        if s["auth"]:
            lines.append(f"password_file {self.pki.passwd}")
        # Listener options must follow `listener`, or Mosquitto opens a default
        # listener on 1883 for them.
        lines.append(f"listener {self.port} {self.host}")
        if s["max_connections"]:
            lines.append(f"max_connections {s['max_connections']}")
        if s["clientid_binding"]:
            lines.append("use_username_as_clientid true")
        if s["mode"] in ("tls", "mtls"):
            lines += [f"cafile {self.pki.ca}", f"certfile {self.pki.server_cert}",
                      f"keyfile {self.pki.server_key}",
                      f"tls_version tlsv{s['tls_version']}"]
        if s["mode"] == "mtls":
            lines += ["require_certificate true", "use_identity_as_username true",
                      f"crlfile {self.pki.crl}"]
        self.conf.write_text("\n".join(lines) + "\n")

    @property
    def probe_host(self) -> str:
        return "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host

    def start(self, **settings) -> None:
        if port_open(self.probe_host, self.port):
            raise RuntimeError(f"{self.host}:{self.port} is already in use; pick another port")
        self.settings.update(settings)
        self._write()
        self.proc = subprocess.Popen(["mosquitto", "-c", str(self.conf)],
                                     stdout=self._log, stderr=self._log)
        deadline = time.monotonic() + 5
        while not port_open(self.probe_host, self.port):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"mosquitto failed to start, see {self.workdir}/mosquitto.log")
            time.sleep(0.02)

    def apply(self, **change) -> str:
        """Applies settings the cheapest way that works: 'reload', 'restart' or ''."""
        old = dict(self.settings)
        self.settings.update(change)
        changed = {k for k in change if old.get(k) != self.settings[k]}
        if not changed:
            return ""
        revoked_certs = "revoked" in changed and self.settings["mode"] == "mtls"
        if changed & set(RESTART_KEYS) or revoked_certs:
            self.restart()
            return "restart"
        self._write()
        os.kill(self.proc.pid, signal.SIGHUP)
        return "reload"

    def restart(self) -> None:
        self.stop()
        self.start()

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
