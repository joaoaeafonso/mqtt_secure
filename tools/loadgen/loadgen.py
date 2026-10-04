#!/usr/bin/env python3
"""Mock MQTT sensors and load-test orchestration for mqtt-secure.

Subcommands
  keys        generate the pre-shared key file used by sensors and gateway
  broker      run a private Mosquitto instance (optionally with the zone ACL)
  sensors     run N mock sensors publishing at a fixed rate
  eavesdrop   subscribe to '#' and count what leaks
  matrix      run the whole thing (broker, gateway, sensors, eavesdropper) for
              every zone x profile x load point and write a results table

Each sensor is its own MQTT connection with client id "sensor-<n>" and key id
<n>, publishing to "<zone>/sensors/sensor-<n>/temp". The first 8 bytes of every
plaintext payload are the send time (ns since epoch, big-endian), which
msec_load_gateway uses to measure end-to-end latency.
"""

from __future__ import annotations

import argparse
import csv
import json
import multiprocessing as mp
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import paho.mqtt.client as mqtt

from msec_envelope import KEY_SIZE, NONE, SENDER_PROTECTION, Protector, read_keys

REPO = Path(__file__).resolve().parents[2]
DEFAULT_GATEWAY = REPO / "build" / "bench" / "apps" / "load_gateway" / "msec_load_gateway"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18830
PROFILES = list(SENDER_PROTECTION)

# zone name -> (broker uses the ACL, topic prefix, gateway subscription)
ZONES = {
    "noacl": (False, "open", "open/#"),
    "open": (True, "open", "open/#"),
    "restricted": (True, "restricted", "restricted/sensors/#"),
}

# Mosquitto acl_file. Same policy as the loopback demo/benchmarks:
#   open/#        every client may read and write
#   restricted/   each sensor may only write its own subtree (%c = client id),
#                 only the user "gateway" may read
# `topic` lines before the first `user` line apply to clients without a username
# (the sensors and the eavesdropper); the gateway connects as user "gateway".
ACL = """\
topic readwrite open/#
pattern write restricted/sensors/%c/#

user gateway
topic readwrite open/#
topic read restricted/sensors/#
"""


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------- keys ---

def write_keys(path: Path, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="ascii") as f:
        f.write("# key id, 32-byte AES key (hex). Test keys only.\n")
        for key_id in range(1, count + 1):
            f.write(f"{key_id} {secrets.token_hex(KEY_SIZE)}\n")
    path.chmod(0o600)


# ------------------------------------------------------------------- broker ---

def broker_config(workdir: Path, host: str, port: int, acl: bool) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    lines = [
        f"listener {port} {host}",
        "allow_anonymous true",
        "persistence false",
        "log_dest stderr",
        "log_type error",
        "log_type warning",
        # Large enough that slow consumers are measured as latency, not loss.
        "max_queued_messages 100000",
    ]
    if acl:
        acl_path = workdir / "acl"
        acl_path.write_text(ACL)
        acl_path.chmod(0o600)
        lines.append(f"acl_file {acl_path}")
    conf = workdir / "mosquitto.conf"
    conf.write_text("\n".join(lines) + "\n")
    return conf


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


def start_broker(workdir: Path, host: str, port: int, acl: bool) -> subprocess.Popen:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            raise RuntimeError(f"{host}:{port} is already in use; pick another --port")
    except OSError:
        pass
    conf = broker_config(workdir, host, port, acl)
    proc = subprocess.Popen(["mosquitto", "-c", str(conf)])
    wait_for_port(host, port)
    return proc


def process_cpu_seconds(pid: int) -> float:
    """utime + stime of a process, from /proc (Linux)."""
    with open(f"/proc/{pid}/stat", encoding="ascii") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


# ------------------------------------------------------------------ sensors ---

@dataclass
class SensorConfig:
    host: str
    port: int
    first_id: int
    count: int
    rate: float          # messages per second, per sensor
    payload: int         # plaintext bytes (>= 8: the timestamp)
    duration: float
    profile: str
    zone_prefix: str
    keys_file: str | None
    qos: int


def new_client(client_id: str) -> mqtt.Client:
    return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                       protocol=mqtt.MQTTv311)


def sensor_worker(cfg: SensorConfig, ids: list[int], start: mp.Barrier,
                  results: mp.Queue) -> None:
    """Runs a group of sensors in one process, without paho's network threads:
    a single loop publishes on schedule and drives the sockets by hand, which
    is far cheaper than one Python thread per connection."""
    protection = SENDER_PROTECTION[cfg.profile]
    keys = read_keys(cfg.keys_file) if protection != NONE else {}
    filler = bytes(max(cfg.payload - 8, 0))

    sensors = []
    for sensor_id in ids:
        client = new_client(f"sensor-{sensor_id}")
        client.connect(cfg.host, cfg.port, keepalive=60)
        topic = f"{cfg.zone_prefix}/sensors/sensor-{sensor_id}/temp"
        key = keys.get(sensor_id) if protection != NONE else None
        if protection != NONE and key is None:
            raise SystemExit(f"no key for sensor id {sensor_id} in {cfg.keys_file}")
        sensors.append((client, topic, topic.encode(), Protector(protection, sensor_id, key)))

    deadline = time.monotonic() + 10
    while not all(c.is_connected() for c, *_ in sensors):
        if time.monotonic() > deadline:
            raise SystemExit("sensors could not connect to the broker")
        for client, *_ in sensors:
            client.loop(timeout=0.001)

    start.wait()
    period = 1.0 / (len(sensors) * cfg.rate)
    begin = time.perf_counter()
    end = begin + cfg.duration
    next_send = begin
    sent = skipped = 0
    last_housekeeping = begin
    index = 0
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        if now < next_send:
            time.sleep(min(next_send - now, 0.002))
            continue
        if now - next_send > 0.25:  # can't keep up: drop the backlog instead of bursting
            missed = int((now - next_send) / period)
            skipped += missed
            next_send += missed * period
        client, topic, topic_bytes, protector = sensors[index]
        index = (index + 1) % len(sensors)
        payload = time.time_ns().to_bytes(8, "big") + filler
        client.publish(topic, protector.protect(topic_bytes, payload), qos=cfg.qos)
        client.loop_write()
        if cfg.qos:
            client.loop_read()
        sent += 1
        next_send += period
        if now - last_housekeeping > 0.5:
            for c, *_ in sensors:
                c.loop_read()
                c.loop_misc()
            last_housekeeping = now
    elapsed = time.perf_counter() - begin

    flush_deadline = time.monotonic() + 5
    while any(c.want_write() for c, *_ in sensors) and time.monotonic() < flush_deadline:
        for c, *_ in sensors:
            if c.want_write():
                c.loop_write()
    for c, *_ in sensors:
        c.disconnect()
        c.loop_write()
    results.put({"sent": sent, "skipped": skipped, "elapsed": elapsed})


def run_sensors(cfg: SensorConfig, processes: int) -> dict:
    processes = max(1, min(processes, cfg.count))
    ids = list(range(cfg.first_id, cfg.first_id + cfg.count))
    groups = [ids[i::processes] for i in range(processes)]
    ctx = mp.get_context("spawn")
    start = ctx.Barrier(processes)
    results = ctx.Queue()
    workers = [ctx.Process(target=sensor_worker, args=(cfg, group, start, results))
               for group in groups]
    for w in workers:
        w.start()
    totals = [results.get() for _ in workers]
    for w in workers:
        w.join()
        if w.exitcode != 0:
            raise RuntimeError(f"sensor worker exited with {w.exitcode}")
    sent = sum(t["sent"] for t in totals)
    elapsed = max(t["elapsed"] for t in totals)
    return {
        "sensors": cfg.count,
        "processes": processes,
        "target_msg_per_s": cfg.count * cfg.rate,
        "sent": sent,
        "skipped": sum(t["skipped"] for t in totals),
        "sent_msg_per_s": sent / elapsed if elapsed else 0.0,
    }


# -------------------------------------------------------------- eavesdropper ---

class Eavesdropper:
    """Client "mallory" subscribed to '#', counting every message it receives."""

    def __init__(self, host: str, port: int) -> None:
        self.received = 0
        self.client = new_client("mallory")
        self.client.on_message = self._on_message
        self._subscribed = threading.Event()
        self.client.on_subscribe = lambda *args: self._subscribed.set()
        self.client.connect(host, port, keepalive=60)
        self.client.loop_start()
        self.client.subscribe("#", qos=0)
        if not self._subscribed.wait(5):
            raise RuntimeError("eavesdropper could not subscribe")

    def _on_message(self, _client, _userdata, _message) -> None:
        self.received += 1

    def stop(self) -> int:
        self.client.disconnect()
        self.client.loop_stop()
        return self.received


# ------------------------------------------------------------------- gateway ---

class Gateway:
    """msec_load_gateway as a subprocess; waits for READY, collects the JSON summary."""

    def __init__(self, binary: Path, host: str, port: int, profile: str, persistence: str,
                 keys_file: Path | None, subscription: str, workdir: Path,
                 verbose: bool) -> None:
        self.summary_path = workdir / "gateway-summary.json"
        self.summary_path.unlink(missing_ok=True)
        cmd = [str(binary), "--broker", f"tcp://{host}:{port}", "--profile", profile,
               "--persistence", persistence, "--subscribe", subscription,
               "--json", str(self.summary_path)]
        if keys_file and profile != "none":
            cmd += ["--keys", str(keys_file)]
        self.proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
        self.ready = threading.Event()
        self.output: list[str] = []
        threading.Thread(target=self._pump, args=(verbose,), daemon=True).start()
        if not self.ready.wait(10):
            self.proc.kill()
            raise RuntimeError("gateway did not become ready:\n" + "".join(self.output))

    def _pump(self, verbose: bool) -> None:
        for line in self.proc.stderr:
            self.output.append(line)
            if line.startswith("READY"):
                self.ready.set()
            if verbose:
                sys.stderr.write(f"  gateway| {line}")

    def stop(self) -> dict:
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise RuntimeError("gateway did not exit")
        if self.proc.returncode != 0 or not self.summary_path.exists():
            raise RuntimeError("gateway failed:\n" + "".join(self.output))
        return json.loads(self.summary_path.read_text())


# -------------------------------------------------------------------- matrix ---

COLUMNS = ["zone", "profile", "persistence", "sensors", "rate", "payload", "target_msg_s",
           "sent_msg_s", "delivered_msg_s", "loss_pct", "rejected", "leak_pct",
           "lat_p50_us", "lat_p99_us", "lat_max_us", "gw_cpu_pct", "gw_cpu_us_per_msg",
           "broker_cpu_pct"]


def run_scenario(args, zone: str, profile: str, sensors: int, rate: float, payload: int,
                 keys_file: Path, workdir: Path, broker: subprocess.Popen) -> dict:
    _, prefix, subscription = ZONES[zone]
    gateway = Gateway(args.gateway, args.host, args.port, profile, args.persistence, keys_file,
                      subscription, workdir, args.verbose)
    eaves = Eavesdropper(args.host, args.port) if not args.no_eavesdropper else None
    broker_cpu_before = process_cpu_seconds(broker.pid)
    t0 = time.perf_counter()
    try:
        load = run_sensors(SensorConfig(host=args.host, port=args.port, first_id=1,
                                        count=sensors, rate=rate, payload=payload,
                                        duration=args.duration, profile=profile,
                                        zone_prefix=prefix, keys_file=str(keys_file),
                                        qos=args.qos),
                           args.processes)
        time.sleep(args.drain)
    finally:
        leaked = eaves.stop() if eaves else 0
        gw = gateway.stop()
    wall = time.perf_counter() - t0
    broker_cpu = process_cpu_seconds(broker.pid) - broker_cpu_before

    sent = load["sent"]
    return {
        "zone": zone, "profile": profile, "persistence": args.persistence,
        "sensors": sensors, "rate": rate, "payload": payload,
        "target_msg_s": round(load["target_msg_per_s"]),
        "sent_msg_s": round(load["sent_msg_per_s"]),
        "delivered_msg_s": round(gw["msg_per_s"]),
        "loss_pct": round(100.0 * (1 - (gw["delivered"] + gw["rejected"]) / sent), 2) if sent else 0.0,
        "rejected": gw["rejected"],
        "leak_pct": round(100.0 * leaked / sent, 1) if sent and eaves else "",
        "lat_p50_us": round(gw["latency_us"]["p50"]),
        "lat_p99_us": round(gw["latency_us"]["p99"]),
        "lat_max_us": round(gw["latency_us"]["max"]),
        "gw_cpu_pct": gw["cpu_pct"],
        "gw_cpu_us_per_msg": gw["cpu_us_per_msg"],
        "broker_cpu_pct": round(100.0 * broker_cpu / wall, 1),
    }


def markdown_table(rows: list[dict]) -> str:
    out = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    out += ["| " + " | ".join(str(r[c]) for c in COLUMNS) + " |" for r in rows]
    return "\n".join(out)


def cmd_matrix(args) -> None:
    if not args.gateway.exists():
        raise SystemExit(f"{args.gateway} not found; build it with: cmake --preset bench && "
                         "cmake --build --preset bench")
    load_points = [(s, r, p) for s in args.sensors for r in args.rates for p in args.payloads]
    total = len(args.zones) * len(args.profiles) * len(load_points)
    out = Path(args.out or REPO / "build" / "loadtest" /
               f"results-{time.strftime('%Y%m%d-%H%M%S')}.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="msec-load-") as tmp:
        workdir = Path(tmp)
        keys_file = workdir / "keys.txt"
        write_keys(keys_file, max(args.sensors))
        n = 0
        # Group by ACL setting so the broker restarts only when its config changes.
        for acl in (False, True):
            zones = [z for z in args.zones if ZONES[z][0] == acl]
            if not zones:
                continue
            broker = start_broker(workdir / ("acl" if acl else "noacl"), args.host, args.port, acl)
            try:
                for zone in zones:
                    for profile in args.profiles:
                        for sensors, rate, payload in load_points:
                            n += 1
                            log(f"[{n}/{total}] {zone}/{profile}: {sensors} sensors x "
                                f"{rate:g} msg/s, {payload} B, {args.duration:g} s")
                            row = run_scenario(args, zone, profile, sensors, rate, payload,
                                               keys_file, workdir, broker)
                            log("    " + ", ".join(f"{k}={row[k]}" for k in COLUMNS[6:]))
                            rows.append(row)
            finally:
                broker.terminate()
                broker.wait(timeout=5)
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(markdown_table(rows))
    log(f"\nresults written to {out}")


# ----------------------------------------------------------------------- CLI ---

def cmd_keys(args) -> None:
    write_keys(Path(args.out), args.count)
    log(f"wrote {args.count} keys to {args.out}")


def cmd_broker(args) -> None:
    workdir = Path(tempfile.mkdtemp(prefix="msec-broker-"))
    broker = start_broker(workdir, args.host, args.port, args.acl)
    log(f"mosquitto on {args.host}:{args.port} ({'zone ACL' if args.acl else 'no ACL'}), "
        f"config in {workdir}; Ctrl-C to stop")
    try:
        broker.wait()
    except KeyboardInterrupt:
        broker.terminate()
        broker.wait(timeout=5)


def cmd_sensors(args) -> None:
    if SENDER_PROTECTION[args.profile] != NONE and not args.keys:
        raise SystemExit("--keys is required unless --profile none")
    result = run_sensors(SensorConfig(host=args.host, port=args.port, first_id=args.first_id,
                                      count=args.sensors, rate=args.rate, payload=args.payload,
                                      duration=args.duration, profile=args.profile,
                                      zone_prefix=ZONES[args.zone][1], keys_file=args.keys,
                                      qos=args.qos),
                         args.processes)
    print(json.dumps(result))


def cmd_eavesdrop(args) -> None:
    eaves = Eavesdropper(args.host, args.port)
    log(f"mallory subscribed to '#' for {args.duration:g} s")
    time.sleep(args.duration)
    print(json.dumps({"received": eaves.stop()}))


def positive_list(kind):
    return lambda text: [kind(v) for v in text.split(",")]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def connection(p):
        p.add_argument("--host", default=DEFAULT_HOST)
        p.add_argument("--port", type=int, default=DEFAULT_PORT)

    p = sub.add_parser("keys", help="generate a key file")
    p.add_argument("--count", type=int, required=True, help="number of sensors (key ids 1..N)")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("broker", help="run a private mosquitto in the foreground")
    connection(p)
    p.add_argument("--acl", action="store_true", help="enforce the open/restricted zone ACL")
    p.set_defaults(func=cmd_broker)

    p = sub.add_parser("sensors", help="run mock sensors")
    connection(p)
    p.add_argument("--sensors", type=int, default=10)
    p.add_argument("--first-id", type=int, default=1)
    p.add_argument("--rate", type=float, default=10, help="msg/s per sensor")
    p.add_argument("--payload", type=int, default=64, help="plaintext bytes (min 8)")
    p.add_argument("--duration", type=float, default=10)
    p.add_argument("--profile", choices=PROFILES, default="full",
                   help="must match the gateway's --profile")
    p.add_argument("--zone", choices=list(ZONES), default="restricted")
    p.add_argument("--keys")
    p.add_argument("--qos", type=int, choices=(0, 1), default=0)
    p.add_argument("--processes", type=int, default=min(4, os.cpu_count() or 1))
    p.set_defaults(func=cmd_sensors)

    p = sub.add_parser("eavesdrop", help="subscribe to '#' and count messages")
    connection(p)
    p.add_argument("--duration", type=float, default=10)
    p.set_defaults(func=cmd_eavesdrop)

    p = sub.add_parser("matrix", help="run every zone x profile x load point")
    connection(p)
    p.add_argument("--gateway", type=Path, default=DEFAULT_GATEWAY)
    p.add_argument("--zones", type=positive_list(str), default=list(ZONES))
    p.add_argument("--profiles", type=positive_list(str), default=["none", "auth_only", "aead", "full"])
    p.add_argument("--persistence", choices=("none", "plain", "at-rest"), default="none")
    p.add_argument("--sensors", type=positive_list(int), default=[100])
    p.add_argument("--rates", type=positive_list(float), default=[10.0, 100.0],
                   help="msg/s per sensor, comma separated")
    p.add_argument("--payloads", type=positive_list(int), default=[64])
    p.add_argument("--duration", type=float, default=10)
    p.add_argument("--drain", type=float, default=2, help="seconds to let queues empty")
    p.add_argument("--qos", type=int, choices=(0, 1), default=0)
    p.add_argument("--processes", type=int, default=min(4, os.cpu_count() or 1))
    p.add_argument("--no-eavesdropper", action="store_true")
    p.add_argument("--out", help="CSV path (default build/loadtest/results-<time>.csv)")
    p.add_argument("--verbose", action="store_true", help="show gateway progress lines")
    p.set_defaults(func=cmd_matrix)

    args = parser.parse_args()
    if getattr(args, "zones", None):
        unknown = set(args.zones) - set(ZONES)
        if unknown:
            parser.error(f"unknown zones: {', '.join(sorted(unknown))}")
    if getattr(args, "profiles", None):
        unknown = set(args.profiles) - set(PROFILES)
        if unknown:
            parser.error(f"unknown profiles: {', '.join(sorted(unknown))}")
    args.func(args)


if __name__ == "__main__":
    main()
