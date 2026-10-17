"""TLS key logging, so Wireshark can decrypt the lab's TLS connections.

Every TLS endpoint in the lab writes its session secrets in the NSS key log
format (the one Wireshark reads) to the file named by SSLKEYLOGFILE:

  Python (sensors, attacker,      ssl.SSLContext.keylog_filename, set by
  agent control channel)          enable() below on every context the lab makes
  mosquitto, msec_load_gateway    LD_PRELOAD of libmsec_sslkeylog.so
                                  (tools/wireshark/sslkeylog.cpp), see preload_env()

Paho's tls_set() builds a bare SSLContext, which ignores SSLKEYLOGFILE, hence
the explicit hook. The secrets decrypt TEST traffic only; never enable this
in a deployment.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

ENV = "SSLKEYLOGFILE"
PRELOAD_NAME = "libmsec_sslkeylog.so"


def path() -> str | None:
    return os.environ.get(ENV) or None


def enable(context: ssl.SSLContext) -> ssl.SSLContext:
    """Logs this context's TLS secrets to $SSLKEYLOGFILE, if set."""
    target = path()
    if target:
        context.keylog_filename = target
    return context


def activate(target: Path) -> Path:
    """Sets SSLKEYLOGFILE for this process and every child it starts from now on.
    The file is created private (0600): it decrypts every captured session."""
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(mode=0o600, exist_ok=True)
    target.chmod(0o600)
    os.environ[ENV] = str(target)
    return target


def library_for(gateway_binary: Path) -> Path:
    """The shim built next to the gateway: build/<preset>/tools/wireshark/."""
    return gateway_binary.resolve().parents[2] / "tools" / "wireshark" / PRELOAD_NAME


def preload_env(library: Path | None) -> dict[str, str] | None:
    """Environment for a native child (mosquitto, the C++ gateway) that makes it
    log its TLS secrets too, or None when key logging is off or the library
    is missing."""
    if not path() or library is None or not library.exists():
        return None
    env = dict(os.environ)
    env["LD_PRELOAD"] = " ".join(p for p in (str(library), env.get("LD_PRELOAD", "")) if p)
    return env
