"""Mock sensor fleet: N MQTT connections spread over worker processes, each
reconfigurable while it runs (rate, payload size, zone, payload protection,
transport).

Sensor <n> connects as client id and username "sensor-<n>", always presents
its password (and, with mtls, its certificate), and seals payloads with key id
<n>. Presenting credentials even when the broker doesn't ask for them means
switching broker authentication on or off never interrupts legitimate traffic.

Plaintext payload: send time (u64 big-endian ns since epoch) + zero padding.

Workers drive their sockets by hand from one loop instead of one paho thread
per connection, which is far cheaper in Python.
"""

from __future__ import annotations

import multiprocessing as mp
import queue
import ssl
import time
from dataclasses import dataclass, field

import paho.mqtt.client as mqtt

from msec_envelope import SENDER_PROTECTION_MODES, Protector, read_keys

RECONNECT_INTERVAL = 1.0
CONNECT_TIMEOUT = 5.0
REPORT_INTERVAL = 0.5


def make_client(client_id: str, transport: dict, username: str | None = None,
                password: str | None = None, cert: tuple[str, str] | None = None) -> mqtt.Client:
    """A paho client set up for the lab's current transport (not yet connected)."""
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                         protocol=mqtt.MQTTv311)
    if username:
        client.username_pw_set(username, password)
    if transport["mode"] in ("tls", "mtls"):
        certfile, keyfile = cert if (cert and transport["mode"] == "mtls") else (None, None)
        client.tls_set(ca_certs=transport["ca"], certfile=certfile, keyfile=keyfile,
                       cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    return client


@dataclass
class Sensor:
    sid: int
    password: str
    protector: Protector
    client: mqtt.Client | None = None
    state: str = "down"            # down | connecting | up
    since: float = 0.0
    error: str = ""
    topic: str = ""
    topic_bytes: bytes = b""

    @property
    def name(self) -> str:
        return f"sensor-{self.sid}"

    def connect(self, transport: dict, clients_dir: str) -> None:
        self.close()
        self.since = time.monotonic()
        try:
            cert = (f"{clients_dir}/{self.name}.crt", f"{clients_dir}/{self.name}.key")
            client = make_client(self.name, transport, self.name, self.password, cert)
            client.connect(transport["host"], transport["port"], keepalive=30)
        except (OSError, ssl.SSLError, ValueError) as e:
            self.state, self.error = "down", str(e) or type(e).__name__
            return
        self.client, self.state = client, "connecting"

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.disconnect()
                self.client.loop_write()
            except Exception:  # noqa: BLE001 - already broken; just drop it
                pass
            sock = self.client.socket()
            if sock is not None:
                sock.close()
        self.client, self.state = None, "down"

    def poll(self) -> None:
        """Processes incoming packets (CONNACK, PINGRESP) and notices dead sockets."""
        if self.client is None:
            return
        try:
            self.client.loop_read()
            self.client.loop_misc()
        except Exception as e:  # noqa: BLE001
            self.error = str(e)
        if self.client.is_connected():
            self.state = "up"
        elif self.state == "up" or time.monotonic() - self.since > CONNECT_TIMEOUT:
            self.error = self.error or "connection lost"
            self.close()


@dataclass
class WorkerSettings:
    ids: list[int]
    keys_file: str
    credentials: dict[str, str]
    clients_dir: str
    transport: dict
    protection: str
    rate: float
    payload: int
    zone: str
    qos: int


@dataclass
class WorkerReport:
    worker: int
    sent: int = 0
    skipped: int = 0
    up: int = 0
    total: int = 0
    last_error: str = ""
    extra: dict = field(default_factory=dict)


def _worker(index: int, cfg: WorkerSettings, control: mp.Queue, reports: mp.Queue,
            stop: mp.Event) -> None:
    keys = read_keys(cfg.keys_file)
    sensors = [Sensor(sid, cfg.credentials[f"sensor-{sid}"],
                      Protector(SENDER_PROTECTION_MODES[cfg.protection], sid, keys[sid]))
               for sid in cfg.ids]
    state = {"transport": cfg.transport, "rate": cfg.rate, "payload": cfg.payload,
             "zone": cfg.zone, "protection": cfg.protection}

    def set_topics() -> None:
        for s in sensors:
            s.topic = f"{state['zone']}/sensors/{s.name}/temp"
            s.topic_bytes = s.topic.encode()

    def connect_all() -> None:
        for s in sensors:
            s.connect(state["transport"], cfg.clients_dir)

    set_topics()
    connect_all()
    report = WorkerReport(worker=index, total=len(sensors))
    filler = bytes(max(state["payload"] - 8, 0))
    period = 1.0 / (len(sensors) * state["rate"]) if state["rate"] > 0 else None
    next_send = time.perf_counter()
    last_poll = last_report = 0.0
    index_rr = 0

    while not stop.is_set():
        # --- control
        try:
            while True:
                change = control.get_nowait()
                state.update(change)
                if "transport" in change:
                    connect_all()
                if "protection" in change:
                    for s in sensors:
                        s.protector.set_protection(SENDER_PROTECTION_MODES[change["protection"]])
                if "zone" in change:
                    set_topics()
                if "payload" in change:
                    filler = bytes(max(state["payload"] - 8, 0))
                if "rate" in change:
                    period = (1.0 / (len(sensors) * state["rate"])
                              if state["rate"] > 0 else None)
                    next_send = time.perf_counter()
        except queue.Empty:
            pass

        now = time.perf_counter()
        # --- housekeeping: CONNACKs, keep-alives, reconnects, reports
        if now - last_poll > 0.05:
            last_poll = now
            mono = time.monotonic()
            for s in sensors:
                if s.state == "down":
                    if mono - s.since > RECONNECT_INTERVAL:
                        s.connect(state["transport"], cfg.clients_dir)
                else:
                    s.poll()
                if s.error:
                    report.last_error, s.error = s.error, ""
        if now - last_report > REPORT_INTERVAL:
            last_report = now
            report.up = sum(1 for s in sensors if s.state == "up")
            if report.up == report.total:
                report.last_error = ""  # recovered; only report errors that still matter
            reports.put(report)

        # --- publish on schedule, round robin over sensors
        if period is None:
            time.sleep(0.01)
            continue
        if now < next_send:
            time.sleep(min(next_send - now, 0.002))
            continue
        if now - next_send > 0.25:  # can't keep up: drop the backlog instead of bursting
            missed = int((now - next_send) / period)
            report.skipped += missed
            next_send += missed * period
        sensor = sensors[index_rr]
        index_rr = (index_rr + 1) % len(sensors)
        next_send += period
        if sensor.state != "up":
            report.skipped += 1
            continue
        plaintext = time.time_ns().to_bytes(8, "big") + filler
        try:
            sensor.client.publish(sensor.topic,
                                  sensor.protector.protect(sensor.topic_bytes, plaintext),
                                  qos=cfg.qos)
            sensor.client.loop_write()
            if cfg.qos:
                sensor.client.loop_read()
            report.sent += 1
        except Exception as e:  # noqa: BLE001
            sensor.error = str(e)
            sensor.close()

    for s in sensors:
        s.close()
    report.up = 0
    reports.put(report)


class SensorFleet:
    """Runs the sensors and aggregates their reports for the controller."""

    def __init__(self, count: int, processes: int, **settings) -> None:
        processes = max(1, min(processes, count))
        ctx = mp.get_context("spawn")
        self.stop_event = ctx.Event()
        self.reports: mp.Queue = ctx.Queue()
        self.controls: list[mp.Queue] = []
        self.workers = []
        self.latest: dict[int, WorkerReport] = {}
        ids = list(range(1, count + 1))
        for index in range(processes):
            control = ctx.Queue()
            cfg = WorkerSettings(ids=ids[index::processes], **settings)
            proc = ctx.Process(target=_worker, args=(index, cfg, control, self.reports,
                                                     self.stop_event), daemon=True)
            proc.start()
            self.controls.append(control)
            self.workers.append(proc)
        self.count = count

    def update(self, **change) -> None:
        for control in self.controls:
            control.put(change)

    def poll(self) -> dict:
        """Latest totals: sent (cumulative), skipped, connected sensors, last error."""
        while True:
            try:
                r = self.reports.get_nowait()
            except queue.Empty:
                break
            self.latest[r.worker] = r
        reports = self.latest.values()
        errors = [r.last_error for r in reports if r.last_error]
        return {"sent": sum(r.sent for r in reports),
                "skipped": sum(r.skipped for r in reports),
                "up": sum(r.up for r in reports),
                "total": self.count,
                "last_error": errors[-1] if errors else ""}

    def stop(self) -> None:
        self.stop_event.set()
        for proc in self.workers:
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
