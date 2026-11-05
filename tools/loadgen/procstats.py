"""Process and socket measurements for the lab, without root or a capture:

  rss_kb(pid)            resident memory now (VmRSS) and its peak (VmHWM)
  tcp_bytes(pid, port)   bytes received/sent by a process on its TCP
                         connections to `port` (Linux tcp_info, via `ss`)
  RssSampler             peak resident memory of several processes over a window
  wire_breakdown(...)    octets per message split into payload, envelope, MQTT
                         and the rest (TLS records, TCP-level MQTT control traffic)

The envelope and MQTT parts are computed from the formats (they are exact:
see docs/protocol/envelope-format.md and MQTT §3.3); the TLS part is what the
socket counted minus everything else, so it also absorbs PINGs, ACKs of QoS
1/2 and reconnects in the window.
"""

from __future__ import annotations

import re
import subprocess
import threading

FIXED_HEADER = 25
NONCE = 12
TAG = 16
SIGNATURE = 64


def _status(pid: int) -> dict[str, int]:
    out = {}
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as f:
            for line in f:
                if line.startswith(("VmRSS:", "VmHWM:")):
                    key, value = line.split(":", 1)
                    out[key] = int(value.split()[0])
    except (OSError, ValueError):
        pass
    return out


def rss_kb(pid: int) -> tuple[int, int]:
    """(current, peak) resident set size in KiB; (0, 0) if the process is gone."""
    s = _status(pid)
    return s.get("VmRSS", 0), s.get("VmHWM", 0)


class RssSampler:
    """Samples VmRSS of some processes every `interval` s; .stop() returns the peaks."""

    def __init__(self, pids: dict[str, int], interval: float = 0.2) -> None:
        self.pids = pids
        self.peaks = dict.fromkeys(pids, 0)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True)
        self._thread.start()

    def _run(self, interval: float) -> None:
        while True:
            for name, pid in self.pids.items():
                self.peaks[name] = max(self.peaks[name], rss_kb(pid)[0])
            if self._stop.wait(interval):
                return

    def stop(self) -> dict[str, int]:
        self._stop.set()
        self._thread.join()
        return self.peaks


_PID_RE = re.compile(r"pid=(\d+)")
_COUNTER_RE = re.compile(r"\b(bytes_received|bytes_acked|bytes_sent):(\d+)")


def tcp_bytes(pid: int, port: int) -> dict[str, int]:
    """Sum of tcp_info byte counters over `pid`'s established connections to `port`."""
    try:
        out = subprocess.run(["ss", "-tinpH", "state", "established", f"( dport = :{port} )"],
                             capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {"received": 0, "sent": 0}
    total = {"received": 0, "sent": 0}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if not any(int(p) == pid for p in _PID_RE.findall(line)):
            continue
        info = lines[i + 1] if i + 1 < len(lines) and not _PID_RE.search(lines[i + 1]) else line
        counters = dict(_COUNTER_RE.findall(info))
        total["received"] += int(counters.get("bytes_received", 0))
        total["sent"] += int(counters.get("bytes_sent", counters.get("bytes_acked", 0)))
    return total


def envelope_overhead(protection: str) -> int:
    """Octets the envelope adds to the plaintext (report §6.4: 53 or 89)."""
    if protection == "none":
        return 0
    if protection == "sign":
        return FIXED_HEADER + SIGNATURE
    return FIXED_HEADER + NONCE + TAG


def _varint_len(n: int) -> int:
    size = 1
    while n >= 128:
        n >>= 7
        size += 1
    return size


def mqtt_publish_size(topic_len: int, body_len: int, qos: int, protocol: str) -> int:
    """Octets of a PUBLISH packet as delivered by the broker (no properties in v5)."""
    remaining = 2 + topic_len + (2 if qos else 0) + (1 if str(protocol) == "5" else 0) + body_len
    return 1 + _varint_len(remaining) + remaining


def wire_breakdown(payload: int, protection: str, topic_len: float, qos: int, protocol: str,
                   wire_per_msg: float | None) -> dict[str, float]:
    envelope = envelope_overhead(protection)
    body = payload + envelope
    mqtt = mqtt_publish_size(round(topic_len), body, qos, protocol) - body
    out = {"bytes_payload": payload, "bytes_envelope": envelope, "bytes_mqtt": mqtt}
    if wire_per_msg:
        out["bytes_wire"] = round(wire_per_msg, 1)
        out["bytes_tls_other"] = round(wire_per_msg - payload - envelope - mqtt, 1)
    else:
        out["bytes_wire"] = out["bytes_tls_other"] = ""
    return out
