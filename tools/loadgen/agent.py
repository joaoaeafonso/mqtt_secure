"""Agent: runs sensors or an attacker on another machine for a lab controller.

    loadgen.py agent --controller HOST:PORT --token TOKEN --fingerprint SHA256 \\
                     --role sensors|attacker [--processes N]

Stays connected and serves one lab run after another; reconnects on its own if
the controller restarts. See cluster.py for the trust bootstrap. Credentials
received for a run live in a private temporary directory (0700) that is
deleted when the run ends or the agent exits.

Clock: the gateway measures one-way latency against the controller's clock, so
the agent estimates its offset to that clock NTP-style over the control
channel (a drift-corrected fit over the lowest-RTT samples, see
ClockEstimator) and has its sensors correct their timestamps. The remaining uncertainty (best RTT / 2) is reported to the
dashboard; sub-millisecond latency needs it to be small, i.e. a quiet LAN, or
clocks synced by PTP (then use --no-clock-correction).
"""

from __future__ import annotations

import collections
import hmac
import shutil
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import keylog
import pki as pki_module
from attacker import Attacker
from cluster import DEFAULT_CONTROL_PORT, PROTOCOL_VERSION, Channel, fingerprint
from sensors import SensorFleet

REPORT_INTERVAL = 0.5
RECONNECT_DELAY = 2.0


class FatalAgentError(Exception):
    """Configuration problems retrying cannot fix (wrong fingerprint or token)."""


class ClockEstimator:
    """Offset of the controller's clock relative to ours, from ping/pong pairs.

    Two unsynchronised clocks drift apart (≈ 10–20 ppm between a Pi without
    NTP and a desktop): over a 60 s window that is up to ~1 ms, more than the
    latencies being measured. So the offset is not taken from one old sample:
    a line offset(t) = a + b·t is fitted to the lowest-RTT quarter of the
    window (the samples least disturbed by queueing) and evaluated *now*.
    Until the window spans MIN_FIT_SPAN_S, or if the fitted drift is not
    plausible for two quartz clocks, it falls back to the lowest-RTT sample.
    """

    MIN_FIT_SPAN_S = 10.0
    MIN_FIT_SAMPLES = 4
    MAX_DRIFT_PPM = 500.0

    def __init__(self, window_s: float = 60.0) -> None:
        self.samples: collections.deque = collections.deque()
        self.window_s = window_s
        self.lock = threading.Lock()

    def add(self, t0: int, t1: int, t2: int, now: float | None = None) -> None:
        """t0/t2: our send/receive time of the ping (ns), t1: the controller's
        time in the pong (ns); `now` (monotonic s) is only for tests."""
        now = time.monotonic() if now is None else now
        rtt = t2 - t0
        offset = t1 - (t0 + t2) // 2
        with self.lock:
            self.samples.append((now, rtt, offset))
            while self.samples and now - self.samples[0][0] > self.window_s:
                self.samples.popleft()

    def estimate(self, now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        with self.lock:
            samples = list(self.samples)
        if not samples:
            return {}
        best = sorted(samples, key=lambda s: s[1])
        # Fallback: the lowest-RTT *recent* sample (after a clock step the
        # older ones are wrong, and without a fit they are stale anyway).
        recent = [s for s in best if now - s[0] <= self.MIN_FIT_SPAN_S] or best
        _, best_rtt, best_offset = recent[0]
        result = {"offset_ns": best_offset, "uncertainty_ns": best_rtt // 2,
                  "samples": len(samples), "drift_ppm": 0.0, "fitted": False}
        chosen = best[:max(self.MIN_FIT_SAMPLES, len(best) // 4)]
        times = [s[0] for s in chosen]
        if len(chosen) < self.MIN_FIT_SAMPLES or max(times) - min(times) < self.MIN_FIT_SPAN_S:
            return result
        # Least squares, centred on the mean time for numerical stability.
        mean_t = sum(times) / len(chosen)
        mean_o = sum(s[2] for s in chosen) / len(chosen)
        sxx = sum((t - mean_t) ** 2 for t in times)
        sxy = sum((s[0] - mean_t) * (s[2] - mean_o) for s in chosen)
        slope_ns_per_s = sxy / sxx
        drift_ppm = slope_ns_per_s / 1e3          # ns/s → µs/s = ppm
        if abs(drift_ppm) > self.MAX_DRIFT_PPM:   # e.g. an NTP step inside the window
            return result
        result.update({"offset_ns": round(mean_o + slope_ns_per_s * (now - mean_t)),
                       "drift_ppm": round(drift_ppm, 3), "fitted": True})
        return result


class Run:
    """One assignment from the controller: a sensor slice or an attacker."""

    def __init__(self, role: str, processes: int) -> None:
        self.role = role
        self.processes = processes
        self.dir = Path(tempfile.mkdtemp(prefix="msec-agent-"))  # created 0700
        self.ids: list[int] = []
        self.keys: dict[str, object] = {}
        self.worker = None

    def make_csrs(self, ids: list[int]) -> dict[str, str]:
        self.ids = ids
        csrs = {}
        for sensor_id in ids:
            name = f"sensor-{sensor_id}"
            key, csr = pki_module.make_csr(name)
            self.keys[name] = key
            csrs[name] = csr
        return csrs

    def transport(self, transport: dict) -> dict:
        return {**transport, "ca": str(self.dir / "ca.crt")}

    def provision(self, message: dict) -> None:
        (self.dir / "ca.crt").write_text(message["ca"])
        settings = dict(message["settings"])
        settings["transport"] = self.transport(settings["transport"])
        if self.role == "attacker":
            self.worker = Attacker(**settings)
            return
        clients = self.dir / "clients"
        for name, cert in message["certs"].items():
            pki_module.write_private(clients / f"{name}.key",
                                     pki_module.key_pem(self.keys.pop(name)))
            (clients / f"{name}.crt").write_text(cert)
        keys_file = self.dir / "keys.txt"
        pki_module.write_private(keys_file, "".join(
            line + "\n" for line in message["keys"]).encode())
        self.worker = SensorFleet(self.ids, self.processes, keys_file=str(keys_file),
                                  credentials=message["passwords"], clients_dir=str(clients),
                                  **settings)

    def update(self, change: dict) -> None:
        if self.worker is None:
            return
        if "transport" in change:
            change = {**change, "transport": self.transport(change["transport"])}
        self.worker.update(**change)

    def stop(self) -> None:
        if self.worker is not None:
            self.worker.stop()
            self.worker = None
        shutil.rmtree(self.dir, ignore_errors=True)


def connect(controller: str, expected_fingerprint: str) -> Channel:
    host, _, port = controller.rpartition(":") if ":" in controller else (controller, "", "")
    raw = socket.create_connection((host, int(port or DEFAULT_CONTROL_PORT)), timeout=10)
    # The certificate is checked by pinning its fingerprint below, so the usual
    # CA/hostname verification is replaced, not skipped.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = keylog.enable(context).wrap_socket(raw)
    presented = fingerprint(tls.getpeercert(binary_form=True))
    if not hmac.compare_digest(presented, expected_fingerprint.lower().removeprefix("sha256:")):
        tls.close()
        raise FatalAgentError(f"controller fingerprint {presented} does not match --fingerprint; "
                              "refusing to send the token")
    tls.settimeout(None)
    return Channel(tls)


def session(args, stop: threading.Event, log) -> None:
    channel = connect(args.controller, args.fingerprint)
    channel.send({"type": "hello", "version": PROTOCOL_VERSION, "token": args.token,
                  "role": args.role, "host": socket.gethostname(), "processes": args.processes})
    welcome = channel.receive()
    if not welcome or welcome.get("type") != "welcome":
        reason = (welcome or {}).get("reason", "connection closed")
        raise FatalAgentError(f"controller rejected this agent: {reason}")
    log(f"joined controller {args.controller} as agent #{welcome['agent_id']} ({args.role})")

    clock = ClockEstimator()
    run: Run | None = None
    applied_offset = None
    closed = threading.Event()

    def background() -> None:
        nonlocal applied_offset
        pings = 0
        last_ping = last_report = 0.0
        while not (stop.is_set() or closed.is_set()):
            now = time.monotonic()
            # Burst of pings at start for a quick estimate, then a steady trickle
            # (one every 0.5 s: ~120 samples per window for the drift fit).
            if now - last_ping > (0.05 if pings < 40 else 0.5):
                last_ping, pings = now, pings + 1
                try:
                    channel.send({"type": "ping", "t0": time.time_ns()})
                except OSError:
                    return
            if now - last_report > REPORT_INTERVAL:
                last_report = now
                estimate = clock.estimate()
                current = run
                if current and current.worker is not None:
                    offset = estimate.get("offset_ns", 0) if args.clock_correction else 0
                    if current.role == "sensors" and (applied_offset is None or
                                                      abs(offset - applied_offset) > 5_000):
                        current.update({"clock_offset_ns": offset})
                        applied_offset = offset
                    data = current.worker.poll()
                else:
                    data = {}
                try:
                    channel.send({"type": "report", "data": data,
                                  "clock": {**estimate, "corrected": args.clock_correction}})
                except OSError:
                    return
            time.sleep(0.01)

    threading.Thread(target=background, daemon=True).start()
    try:
        while not stop.is_set() and (message := channel.receive()) is not None:
            kind = message.get("type")
            try:
                if kind == "pong":
                    clock.add(message["t0"], message["t1"], time.time_ns())
                elif kind == "assign":
                    if run:
                        run.stop()
                    run = Run(message["role"], args.processes)
                    applied_offset = None
                    if message["role"] == "sensors":
                        log(f"assigned {len(message['ids'])} sensors "
                            f"(sensor-{message['ids'][0]}..sensor-{message['ids'][-1]})")
                        channel.send({"type": "csrs", "csrs": run.make_csrs(message["ids"])})
                    else:
                        log("assigned the attacker role")
                elif kind == "provision" and run:
                    run.provision(message)
                    channel.send({"type": "started"})
                elif kind == "update" and run:
                    run.update(message["change"])
                elif kind == "poll":
                    # A measurement edge: totals as of now, not the last 0.5 s report.
                    worker = run.worker if run else None
                    data = worker.fresh_poll() if hasattr(worker, "fresh_poll") else {}
                    channel.send({"type": "fresh", "data": data})
                elif kind == "release":
                    if run:
                        run.stop()
                        run = None
                        log("released")
                    channel.send({"type": "released"})
            except (KeyError, ValueError, OSError) as e:
                channel.send({"type": "error", "message": f"{kind}: {e}"})
    finally:
        closed.set()
        if run:
            run.stop()
        channel.close()


def run_agent(args, log) -> None:
    stop = threading.Event()
    while not stop.is_set():
        try:
            session(args, stop, log)
            log("controller closed the connection")
        except FatalAgentError:
            raise
        except (OSError, ssl.SSLError) as e:
            log(f"controller unreachable ({e}); retrying")
        except KeyboardInterrupt:
            return
        try:
            time.sleep(RECONNECT_DELAY)
        except KeyboardInterrupt:
            return
