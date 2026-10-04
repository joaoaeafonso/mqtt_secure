"""The attacker ("mallory"): a client with broker access but no secrets.

It knows the broker address and the public CA certificate, nothing else: no
password, no client certificate, no payload key. While enabled it

  - stays connected and subscribed to '#', counting what it receives (leak),
  - optionally impersonates the gateway (username "gateway", no password),
  - injects forged plaintext into a sensor's topic at `inject_rate` msg/s
    (payload: send time + "FORGED!!", which the gateway counts if accepted),
  - re-publishes captured messages at `replay_rate` msg/s.

Each security switch shows up in its reports: auth or mtls keep it off the
broker, the ACL starves '#' and blocks injections, payload protection makes
what it sees unreadable and its forgeries/replays bounce off the gateway.
"""

from __future__ import annotations

import collections
import multiprocessing as mp
import queue
import random
import ssl
import threading
import time

from sensors import make_client

REPORT_INTERVAL = 0.5
FORGED_MARKER = b"FORGED!!"


def _run(settings: dict, control: mp.Queue, reports: mp.Queue, stop: mp.Event) -> None:
    state = dict(settings)
    lock = threading.Lock()
    captured: collections.deque = collections.deque(maxlen=500)
    counters = {"received": 0, "injected": 0, "replayed": 0}
    status = {"connected": False, "detail": "idle"}
    client = None

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
        return "gateway" if state["impersonate"] else "mallory"

    def on_message(_c, _userdata, message):
        with lock:
            counters["received"] += 1
            if "/sensors/" in message.topic:
                captured.append((message.topic, bytes(message.payload)))

    def disconnect() -> None:
        nonlocal client
        if client is not None:
            client.disconnect()
            client.loop_stop()
            client = None
        status.update(connected=False, detail="idle")

    def connect() -> None:
        nonlocal client
        disconnect()
        if not state["enabled"]:
            return
        transport = state["transport"]
        try:
            # No password, no client certificate: it has neither.
            client = make_client(f"mallory-{random.randrange(1 << 30)}", transport, identity())
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

    connect()
    next_inject = next_replay = last_report = time.monotonic()
    while not stop.is_set():
        try:
            while True:
                change = control.get_nowait()
                reconnect = any(k in change for k in ("enabled", "impersonate", "transport"))
                state.update(change)
                if reconnect:
                    connect()
        except queue.Empty:
            pass

        now = time.monotonic()
        if client is not None and status["connected"]:
            if state["inject_rate"] > 0 and now >= next_inject:
                topic = f"{state['zone']}/sensors/sensor-1/temp"
                payload = time.time_ns().to_bytes(8, "big") + FORGED_MARKER + bytes(8)
                client.publish(topic, payload, qos=0)
                counters["injected"] += 1
                next_inject = max(next_inject + 1 / state["inject_rate"], now - 1)
            if state["replay_rate"] > 0 and now >= next_replay:
                with lock:
                    sample = random.choice(captured) if captured else None
                if sample:
                    client.publish(sample[0], sample[1], qos=0)
                    counters["replayed"] += 1
                next_replay = max(next_replay + 1 / state["replay_rate"], now - 1)
        if now - last_report > REPORT_INTERVAL:
            last_report = now
            with lock:
                reports.put({**counters, **status, "identity": identity(),
                             "enabled": state["enabled"], "captured": len(captured)})
        time.sleep(0.005)
    disconnect()


class Attacker:
    def __init__(self, **settings) -> None:
        ctx = mp.get_context("spawn")
        self.control = ctx.Queue()
        self.reports = ctx.Queue()
        self.stop_event = ctx.Event()
        self.latest = {"received": 0, "injected": 0, "replayed": 0, "connected": False,
                       "detail": "starting", "identity": "mallory",
                       "enabled": settings["enabled"], "captured": 0}
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
