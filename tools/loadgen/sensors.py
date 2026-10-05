"""Mock sensor fleet: N MQTT connections spread over worker processes, each
reconfigurable while it runs (rate, payload size, zone, payload protection,
transport, protocol, keys).

Sensor <n> connects as client id and username "sensor-<n>", always presents
its password (and, with mtls, its certificate), and seals payloads with its
current key (id = epoch * 1e6 + n). Presenting credentials even when the
broker doesn't ask for them means switching broker authentication on or off
never interrupts legitimate traffic.

Plaintext payload: send time (u64 big-endian ns since epoch) + zero padding.
On agent machines the send time is corrected by the agent's estimated clock
offset to the controller (`clock_offset_ns`), so the gateway can compute
one-way latency against its own clock.

Every sensor is also an actuator: it subscribes to <zone>/actuators/sensor-<n>/cmd
and verifies the gateway's commands with msec_envelope.Verifier (accepted
mode, freshness, sender = a gateway key, replay window). It counts accepted,
rejected, forged-but-accepted ("FORGED-C" at offset 8) and replayed-but-
accepted commands (a command id seen before), so downlink attacks show up
like uplink ones.

Workers drive their sockets by hand from one loop instead of one paho thread
per connection, which is far cheaper in Python.
"""

from __future__ import annotations

import collections
import multiprocessing as mp
import queue
import ssl
import time
from dataclasses import dataclass, field

import paho.mqtt.client as mqtt

from msec_envelope import (GATEWAY_OWNER, NONE, SENDER_PROTECTION_MODES, KeySet, Protector,
                           Rejected, Verifier, add_line, read_keys)

RECONNECT_INTERVAL = 1.0
CONNECT_TIMEOUT = 5.0
REPORT_INTERVAL = 0.5
EPOCH_STRIDE = 1_000_000
FORGED_COMMAND = b"FORGED-C"
SEEN_COMMANDS = 4096


def make_client(client_id: str, transport: dict, username: str | None = None,
                password: str | None = None, cert: tuple[str, str] | None = None) -> mqtt.Client:
    """A paho client set up for the lab's current transport (not yet connected)."""
    protocol = mqtt.MQTTv5 if str(transport.get("protocol", "3.1.1")) == "5" else mqtt.MQTTv311
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=protocol)
    if username:
        client.username_pw_set(username, password)
    if transport["mode"] in ("tls", "mtls"):
        certfile, keyfile = cert if (cert and transport["mode"] == "mtls") else (None, None)
        client.tls_set(ca_certs=transport["ca"], certfile=certfile, keyfile=keyfile,
                       cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    return client


@dataclass
class Counters:
    sent: int = 0
    skipped: int = 0
    kicked: int = 0          # connections lost while up (e.g. session taken over)
    cmd_ok: int = 0
    cmd_rejected: int = 0
    cmd_forged_ok: int = 0
    cmd_replay_ok: int = 0
    cmd_rejected_by: dict = field(default_factory=dict)


@dataclass
class Sensor:
    sid: int
    password: str
    protector: Protector
    verifier: Verifier
    counters: Counters
    client: mqtt.Client | None = None
    state: str = "down"            # down | connecting | up
    since: float = 0.0
    error: str = ""
    topic: str = ""
    topic_bytes: bytes = b""
    command_topic: str = ""
    seen_commands: collections.OrderedDict = field(default_factory=collections.OrderedDict)

    @property
    def name(self) -> str:
        return f"sensor-{self.sid}"

    def connect(self, transport: dict, clients_dir: str) -> None:
        self.close()
        self.since = time.monotonic()
        try:
            cert = (f"{clients_dir}/{self.name}.crt", f"{clients_dir}/{self.name}.key")
            client = make_client(self.name, transport, self.name, self.password, cert)
            client.on_message = self.on_command
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

    def subscribe_commands(self, qos: int) -> None:
        if self.client is not None and self.state == "up":
            self.client.subscribe(self.command_topic, qos=qos)
            self.client.loop_write()

    def poll(self, qos: int) -> None:
        """Processes incoming packets (CONNACK, commands, PINGRESP), notices dead sockets."""
        if self.client is None:
            return
        try:
            self.client.loop_read()
            self.client.loop_write()
            self.client.loop_misc()
        except Exception as e:  # noqa: BLE001
            self.error = str(e)
        if self.client.is_connected():
            if self.state != "up":
                self.state = "up"
                self.subscribe_commands(qos)
        elif self.state == "up" or time.monotonic() - self.since > CONNECT_TIMEOUT:
            if self.state == "up":
                self.counters.kicked += 1
            self.error = self.error or "connection lost"
            self.close()

    def on_command(self, _client, _userdata, message) -> None:
        c = self.counters
        payload = bytes(message.payload)
        if self.protector.protection != NONE:
            try:
                payload = self.verifier.open(message.topic.encode(), payload)
            except Rejected as e:
                c.cmd_rejected += 1
                c.cmd_rejected_by[e.reason] = c.cmd_rejected_by.get(e.reason, 0) + 1
                return
        if payload[8:16] == FORGED_COMMAND:
            c.cmd_forged_ok += 1
            return
        command_id = payload[8:16]
        if command_id in self.seen_commands:
            c.cmd_replay_ok += 1
            return
        self.seen_commands[command_id] = None
        if len(self.seen_commands) > SEEN_COMMANDS:
            self.seen_commands.popitem(last=False)
        c.cmd_ok += 1


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
    freshness: bool = True
    replay: bool = True
    epoch: int = 0


@dataclass
class WorkerReport:
    worker: int
    sent: int = 0
    skipped: int = 0
    up: int = 0
    total: int = 0
    kicked: int = 0
    cmd_ok: int = 0
    cmd_rejected: int = 0
    cmd_forged_ok: int = 0
    cmd_replay_ok: int = 0
    cmd_rejected_by: dict = field(default_factory=dict)
    last_error: str = ""


def gateway_keys(keys: KeySet) -> set[int]:
    return {kid for kid, owner in keys.owners.items() if owner == GATEWAY_OWNER}


def _worker(index: int, cfg: WorkerSettings, control: mp.Queue, reports: mp.Queue,
            stop: mp.Event) -> None:
    keys = read_keys(cfg.keys_file)
    counters = Counters()
    state = {"transport": cfg.transport, "rate": cfg.rate, "payload": cfg.payload,
             "zone": cfg.zone, "protection": cfg.protection, "clock_offset_ns": 0,
             "freshness": cfg.freshness, "replay": cfg.replay, "epoch": cfg.epoch}

    def make_verifier() -> Verifier:
        mode = SENDER_PROTECTION_MODES[state["protection"]]
        return Verifier(keys, {mode} if mode != NONE else set(), freshness=state["freshness"],
                        replay=state["replay"], allowed_senders=gateway_keys(keys))

    def make_sensor(sid: int) -> Sensor:
        kid = state["epoch"] * EPOCH_STRIDE + sid
        protector = Protector(NONE, kid, keys.aead.get(kid), keys.sign_private.get(kid))
        protector.set_protection(SENDER_PROTECTION_MODES[state["protection"]])
        return Sensor(sid, cfg.credentials[f"sensor-{sid}"], protector, make_verifier(), counters)

    sensors = [make_sensor(sid) for sid in cfg.ids]

    def set_topics() -> None:
        for s in sensors:
            s.topic = f"{state['zone']}/sensors/{s.name}/temp"
            s.topic_bytes = s.topic.encode()
            s.command_topic = f"{state['zone']}/actuators/{s.name}/cmd"

    def connect_all() -> None:
        for s in sensors:
            s.connect(state["transport"], cfg.clients_dir)

    def apply_policy() -> None:
        mode = SENDER_PROTECTION_MODES[state["protection"]]
        for s in sensors:
            s.protector.set_protection(mode)
            s.verifier.accept = {mode} if mode != NONE else set()
            s.verifier.freshness, s.verifier.replay = state["freshness"], state["replay"]
            s.verifier.allowed_senders = gateway_keys(keys)

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
                state.update({k: v for k, v in change.items() if k in state})
                if "add_keys" in change:  # rotation, step 1: new keys next to the old ones
                    for line in change["add_keys"]:
                        add_line(keys, line)
                if "epoch" in change:     # rotation, step 2: send with the new keys
                    for s in sensors:
                        kid = state["epoch"] * EPOCH_STRIDE + s.sid
                        if kid in keys.aead:  # a revoked sensor gets no new keys
                            s.protector.rekey(kid, keys.aead[kid], keys.sign_private.get(kid))
                if "drop_keys" in change:  # rotation, step 3: forget the old ones
                    for kid in change["drop_keys"]:
                        keys.remove(kid)
                        for s in sensors:
                            s.verifier.forget(kid)
                if change.keys() & {"protection", "freshness", "replay", "add_keys",
                                    "drop_keys", "epoch"}:
                    apply_policy()
                if "zone" in change:
                    for s in sensors:
                        if s.client is not None and s.state == "up":
                            s.client.unsubscribe(s.command_topic)
                    set_topics()
                    for s in sensors:
                        s.subscribe_commands(cfg.qos)
                if "transport" in change:
                    connect_all()
                if "payload" in change:
                    filler = bytes(max(state["payload"] - 8, 0))
                if "rate" in change:
                    period = (1.0 / (len(sensors) * state["rate"])
                              if state["rate"] > 0 else None)
                    next_send = time.perf_counter()
        except queue.Empty:
            pass

        now = time.perf_counter()
        # --- housekeeping: CONNACKs, commands, keep-alives, reconnects, reports
        if now - last_poll > 0.05:
            last_poll = now
            mono = time.monotonic()
            for s in sensors:
                if s.state == "down":
                    if mono - s.since > RECONNECT_INTERVAL:
                        s.connect(state["transport"], cfg.clients_dir)
                else:
                    s.poll(cfg.qos)
                if s.error:
                    report.last_error, s.error = s.error, ""
        if now - last_report > REPORT_INTERVAL:
            last_report = now
            report.up = sum(1 for s in sensors if s.state == "up")
            for name in ("sent", "skipped", "kicked", "cmd_ok", "cmd_rejected", "cmd_forged_ok",
                         "cmd_replay_ok"):
                setattr(report, name, getattr(counters, name))
            report.cmd_rejected_by = dict(counters.cmd_rejected_by)
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
            counters.skipped += missed
            next_send += missed * period
        sensor = sensors[index_rr]
        index_rr = (index_rr + 1) % len(sensors)
        next_send += period
        if sensor.state != "up":
            counters.skipped += 1
            continue
        plaintext = (time.time_ns() + state["clock_offset_ns"]).to_bytes(8, "big") + filler
        try:
            sensor.client.publish(sensor.topic,
                                  sensor.protector.protect(sensor.topic_bytes, plaintext),
                                  qos=cfg.qos)
            sensor.client.loop_write()
            if cfg.qos:
                sensor.client.loop_read()
            counters.sent += 1
        except Exception as e:  # noqa: BLE001
            sensor.error = str(e)
            sensor.close()

    for s in sensors:
        s.close()
    report.up = 0
    reports.put(report)


class SensorFleet:
    """Runs the sensors and aggregates their reports for the controller."""

    def __init__(self, ids: list[int], processes: int, **settings) -> None:
        count = len(ids)
        processes = max(1, min(processes, count))
        ctx = mp.get_context("spawn")
        self.stop_event = ctx.Event()
        self.reports: mp.Queue = ctx.Queue()
        self.controls: list[mp.Queue] = []
        self.workers = []
        self.ids = list(ids)
        self.latest: dict[int, WorkerReport] = {}
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
        """Latest totals: cumulative counters, connected sensors, last error."""
        while True:
            try:
                r = self.reports.get_nowait()
            except queue.Empty:
                break
            self.latest[r.worker] = r
        return summarize(list(self.latest.values()), self.count)

    def stop(self) -> None:
        self.stop_event.set()
        for proc in self.workers:
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()


SUMMED = ("sent", "skipped", "up", "kicked", "cmd_ok", "cmd_rejected", "cmd_forged_ok",
          "cmd_replay_ok")


def summarize(reports: list, total: int) -> dict:
    """Adds up worker (or agent) reports; works on objects and on dicts."""
    get = (lambda r, k, d=0: r.get(k, d)) if reports and isinstance(reports[0], dict) else (
        lambda r, k, d=0: getattr(r, k, d))
    out = {k: sum(get(r, k) for r in reports) for k in SUMMED}
    by: dict = {}
    for r in reports:
        for reason, n in (get(r, "cmd_rejected_by", {}) or {}).items():
            by[reason] = by.get(reason, 0) + n
    errors = [get(r, "last_error", "") for r in reports if get(r, "last_error", "")]
    out.update(total=total, cmd_rejected_by=by, last_error=errors[-1] if errors else "")
    return out

