"""The load lab: broker + gateway + sensors + attacker, all driven by one config
in which every security feature can be switched, at startup or while running.

    [transport]  mode plain|tls|mtls, auth, acl          broker + every client
    [payload]    protection none|auth_only|encrypt,
                 freshness, replay                        gateway + sensors
    [storage]    persistence none|plain|at-rest           gateway
    [load]       rate, payload, zone (live); sensors, processes, qos (startup)
    [attacker]   enabled, impersonate, inject_rate, replay_rate
    [cluster]    sensor_agents, attacker_agents: run those on other machines
                 (see cluster.py / agent.py); 0 = run them on this machine

Lab.apply() takes a partial config, validates it and performs exactly the
actions each change needs (reload, restart + reconnect, or a pipeline switch).
A sampler records one metrics point per second for the dashboard and matrix.
"""

from __future__ import annotations

import collections
import copy
import shutil
import tempfile
import threading
import time
from pathlib import Path

import pki as pki_module
from attacker import Attacker
from broker import Broker
from cluster import (AttackerGroup, ControlServer, FleetGroup, RemoteAttacker, RemoteSensors,
                     primary_address)
from gateway import GatewayProcess
from sensors import SensorFleet

DEFAULTS: dict = {
    "broker": {"host": "127.0.0.1", "port": 18830, "advertise": ""},
    "transport": {"mode": "plain", "auth": False, "acl": True},
    "payload": {"protection": "encrypt", "freshness": True, "replay": True},
    "storage": {"persistence": "none"},
    "load": {"sensors": 50, "rate": 20.0, "payload": 64, "zone": "restricted", "qos": 0,
             "processes": 2},
    "attacker": {"enabled": True, "impersonate": False, "inject_rate": 0.0,
                 "replay_rate": 0.0},
    "cluster": {"listen": "0.0.0.0", "port": 8089, "sensor_agents": 0, "attacker_agents": 0,
                "join_timeout": 600.0},
}

# Allowed values: a tuple of choices, or a type.
SPEC: dict = {
    "broker": {"host": str, "port": int, "advertise": str},
    "transport": {"mode": ("plain", "tls", "mtls"), "auth": bool, "acl": bool},
    "payload": {"protection": ("none", "auth_only", "encrypt"), "freshness": bool,
                "replay": bool},
    "storage": {"persistence": ("none", "plain", "at-rest")},
    "load": {"sensors": int, "rate": float, "payload": int, "zone": ("open", "restricted"),
             "qos": (0, 1), "processes": int},
    "attacker": {"enabled": bool, "impersonate": bool, "inject_rate": float,
                 "replay_rate": float},
    "cluster": {"listen": str, "port": int, "sensor_agents": int, "attacker_agents": int,
                "join_timeout": float},
}

STARTUP_ONLY = {("broker", "host"), ("broker", "port"), ("broker", "advertise"),
                ("load", "sensors"), ("load", "processes"), ("load", "qos")} | {
                ("cluster", k) for k in SPEC["cluster"]}
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def uses_agents(config: dict) -> bool:
    return config["cluster"]["sensor_agents"] > 0 or config["cluster"]["attacker_agents"] > 0


def advertised_host(config: dict) -> str:
    """The broker address every client (local or remote) connects to."""
    b = config["broker"]
    if b["advertise"]:
        return b["advertise"]
    if b["host"] in ("0.0.0.0", "::"):
        return primary_address()
    return b["host"]


def validate(patch: dict) -> list[tuple[str, str, object]]:
    """Flattens a partial config into (section, key, value), checking every value."""
    changes = []
    for section, values in patch.items():
        if section not in SPEC or not isinstance(values, dict):
            raise ValueError(f"unknown section [{section}]")
        for key, value in values.items():
            rule = SPEC[section].get(key)
            if rule is None:
                raise ValueError(f"unknown setting {section}.{key}")
            if isinstance(rule, tuple):
                if value not in rule:
                    raise ValueError(f"{section}.{key} must be one of {', '.join(map(str, rule))}")
            elif rule is float:
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    raise ValueError(f"{section}.{key} must be a non-negative number")
                value = float(value)
            elif rule is int:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"{section}.{key} must be a non-negative integer")
            elif not isinstance(value, rule):
                raise ValueError(f"{section}.{key} must be {rule.__name__}")
            changes.append((section, key, value))
    return changes


def merged(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for section, key, value in validate(patch):
        out[section][key] = value
    if out["load"]["payload"] < 8:
        raise ValueError("load.payload must be at least 8 bytes (the timestamp)")
    if out["load"]["sensors"] < 1:
        raise ValueError("load.sensors must be at least 1")
    if out["cluster"]["sensor_agents"] > out["load"]["sensors"]:
        raise ValueError("cluster.sensor_agents cannot exceed load.sensors")
    if uses_agents(out) and out["broker"]["host"] in LOOPBACK:
        raise ValueError("remote agents need the broker on the network: set broker.host = "
                         "\"0.0.0.0\" (and broker.advertise to the address agents use)")
    return out


def describe(section: str, key: str, old, new) -> str:
    fmt = lambda v: ("on" if v else "off") if isinstance(v, bool) else str(v)  # noqa: E731
    return f"{section}.{key}: {fmt(old)} → {fmt(new)}"


class Lab:
    def __init__(self, config: dict, gateway_binary: Path, workdir: Path | None = None,
                 verbose: bool = False, log=print, cluster: ControlServer | None = None) -> None:
        self.config = merged(DEFAULTS, config)
        self.cluster = cluster
        if uses_agents(self.config) and cluster is None:
            raise ValueError("cluster.*_agents > 0 needs a control server")
        self.gateway_binary = gateway_binary
        self.verbose = verbose
        self.log = log
        self._own_workdir = workdir is None
        self.workdir = Path(workdir or tempfile.mkdtemp(prefix="msec-lab-"))
        self.lock = threading.RLock()
        self.history: collections.deque = collections.deque(maxlen=900)
        self.events: collections.deque = collections.deque(maxlen=200)
        self._stop = threading.Event()
        self.broker = self.gateway = self.fleet = self.attacker = None

    # ---------------------------------------------------------------- setup ---

    def transport(self) -> dict:
        b, t = self.config["broker"], self.config["transport"]
        return {"mode": t["mode"], "host": self.advertise, "port": b["port"],
                "ca": str(self.pki.ca)}

    def start(self) -> None:
        c = self.config
        n_sensors, cl = c["load"]["sensors"], c["cluster"]
        self.advertise = advertised_host(c)
        sensor_ids = list(range(1, n_sensors + 1))

        # Reserve agents first: nothing else is worth starting until they are here.
        sensor_agents = attacker_agents = []
        if uses_agents(c):
            self.log(f"agents join with:\n  {self.cluster.join_command(self.cluster_address())}")
            sensor_agents = self._claim("sensors", cl["sensor_agents"])
            attacker_agents = self._claim("attacker", cl["attacker_agents"])
        local_ids = [] if sensor_agents else sensor_ids
        ca = self.cluster.identity.ca if self.cluster else pki_module.CertificateAuthority.create()

        self.log(f"credentials for {n_sensors} sensors in {self.workdir}")
        self.pki = pki_module.generate(self.workdir, ca, sensor_ids, local_ids,
                                       server_names=[self.advertise])
        self.broker = Broker(self.workdir, self.pki, c["broker"]["host"], c["broker"]["port"])
        self.broker.start(c["transport"]["mode"], c["transport"]["auth"], c["transport"]["acl"])
        self.gateway = GatewayProcess(self.gateway_binary, self.pki, self.advertise,
                                      c["broker"]["port"], c, self.verbose)

        settings = {"transport": self.transport(), "protection": c["payload"]["protection"],
                    "rate": c["load"]["rate"], "payload": c["load"]["payload"],
                    "zone": c["load"]["zone"], "qos": c["load"]["qos"]}
        if sensor_agents:
            passwords = pki_module.read_credentials(self.pki.credentials)
            keys = {int(line.split()[0]): line.split()[1]
                    for line in self.pki.keys.read_text().splitlines()
                    if line and not line.startswith("#")}
            slices = [sensor_ids[i::len(sensor_agents)] for i in range(len(sensor_agents))]
            members = []
            for agent, ids in zip(sensor_agents, slices):
                self.log(f"provisioning {len(ids)} sensors on {agent.host}")
                members.append(RemoteSensors(agent, ids, ca, passwords, keys, settings))
            self.fleet = FleetGroup(members, [a.host for a in sensor_agents])
        else:
            self.fleet = FleetGroup([SensorFleet(
                local_ids, c["load"]["processes"], keys_file=str(self.pki.keys),
                credentials=pki_module.read_credentials(self.pki.credentials),
                clients_dir=str(self.pki.clients_dir), **settings)], ["local"])

        attack = {"transport": self.transport(), "zone": c["load"]["zone"], **c["attacker"]}
        if attacker_agents:
            self.attacker = AttackerGroup([RemoteAttacker(a, ca, attack) for a in attacker_agents],
                                          [a.host for a in attacker_agents])
        else:
            self.attacker = AttackerGroup([Attacker(**attack)], ["local"])
        self._event("lab started")
        threading.Thread(target=self._sampler, daemon=True).start()

    def cluster_address(self) -> str:
        listen = self.config["cluster"]["listen"]
        return self.advertise if listen in ("0.0.0.0", "::") else listen

    def _claim(self, role: str, count: int) -> list:
        if count == 0:
            return []
        return self.cluster.claim(role, count, self.config["cluster"]["join_timeout"],
                                  self._stop, announce=lambda m: self.log(f"· {m}"))

    def stop(self) -> None:
        self._stop.set()
        for part in (self.attacker, self.fleet, self.gateway, self.broker):
            if part is not None:
                try:
                    part.stop()
                except Exception as e:  # noqa: BLE001 - keep shutting the rest down
                    self.log(f"stopping {type(part).__name__}: {e}")
        if self._own_workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)

    # --------------------------------------------------------------- control ---

    def apply(self, patch: dict) -> list[str]:
        """Applies a partial config while everything runs. Returns what changed."""
        with self.lock:
            if self.attacker is None:
                raise ValueError("the lab is still starting (waiting for agents?)")
            new = merged(self.config, patch)
            changed = [(s, k, self.config[s][k], new[s][k]) for s, k, _ in validate(patch)
                       if self.config[s][k] != new[s][k]]
            for s, k, _, _ in changed:
                if (s, k) in STARTUP_ONLY:
                    raise ValueError(f"{s}.{k} can only be set at startup")
            if not changed:
                return []
            keys = {(s, k) for s, k, _, _ in changed}
            self.config = new
            t, p = new["transport"], new["payload"]

            if keys & {("transport", "auth"), ("transport", "acl")}:
                self.broker.reload(t["auth"], t["acl"])
            if ("transport", "mode") in keys:
                self.broker.restart(t["mode"])
                self.gateway.set("transport", t["mode"])
                self.gateway.reconnect()
                self.fleet.update(transport=self.transport())
                self.attacker.update(transport=self.transport())
            if ("payload", "protection") in keys:
                self.gateway.set("protection", p["protection"])
                self.fleet.update(protection=p["protection"])
            for key in ("freshness", "replay"):
                if ("payload", key) in keys:
                    self.gateway.set(key, p[key])
            if ("storage", "persistence") in keys:
                self.gateway.set("persistence", new["storage"]["persistence"])
            load = {k: new["load"][k] for s, k in keys if s == "load"}
            if load:
                self.fleet.update(**load)
                if "zone" in load:
                    self.attacker.update(zone=load["zone"])
            attack = {k: new["attacker"][k] for s, k in keys if s == "attacker"}
            if attack:
                self.attacker.update(**attack)

            descriptions = [describe(*c) for c in changed]
            for d in descriptions:
                self._event(d)
            return descriptions

    def _event(self, text: str) -> None:
        self.events.append({"t": time.time(), "text": text})
        self.log(f"· {text}")

    # --------------------------------------------------------------- metrics ---

    def _sampler(self) -> None:
        prev = None
        while not self._stop.wait(1.0):
            now = time.time()
            raw = {
                "t": now,
                "fleet": self.fleet.poll(),
                "gateway": dict(self.gateway.latest),
                "attacker": self.attacker.poll(),
                "broker_cpu_s": self.broker.cpu_seconds(),
                "broker_pid": self.broker.proc.pid,
            }
            if prev is not None:
                self.history.append(self._point(prev, raw))
            prev = raw

    @staticmethod
    def _point(prev: dict, cur: dict) -> dict:
        dt = max(cur["t"] - prev["t"], 1e-6)

        def rate(new, old):
            # Counters restart from 0 on a gateway `reset` or a broker restart.
            return max(new - old if new >= old else new, 0) / dt

        f0, f1 = prev["fleet"], cur["fleet"]
        g0, g1 = prev["gateway"], cur["gateway"]
        a0, a1 = prev["attacker"], cur["attacker"]
        g = lambda d, k: d.get(k, 0)  # noqa: E731
        reasons = set(g1.get("rejected_by", {})) | set(g0.get("rejected_by", {}))
        same_broker = prev["broker_pid"] == cur["broker_pid"]
        return {
            "t": cur["t"],
            "sent": rate(f1["sent"], f0["sent"]),
            "skipped": rate(f1["skipped"], f0["skipped"]),
            "sensors_up": f1["up"], "sensors_total": f1["total"],
            "sensor_error": f1["last_error"],
            "gw_connected": bool(g1.get("connected")),
            "delivered": rate(g(g1, "delivered"), g(g0, "delivered")),
            "rejected": rate(g(g1, "rejected"), g(g0, "rejected")),
            "rejected_by": {r: rate(g1.get("rejected_by", {}).get(r, 0),
                                    g0.get("rejected_by", {}).get(r, 0)) for r in reasons},
            "forged_ok": rate(g(g1, "forged_accepted"), g(g0, "forged_accepted")),
            "replays_ok": rate(g(g1, "replays_accepted"), g(g0, "replays_accepted")),
            "lat_p50": g(g1, "lat_p50_us"), "lat_p99": g(g1, "lat_p99_us"),
            "gw_cpu": g(g1, "cpu_pct"),
            "broker_cpu": (100.0 * rate(cur["broker_cpu_s"], prev["broker_cpu_s"])
                           if same_broker else 0.0),
            "eavesdropped": rate(a1["received"], a0["received"]),
            "injected": rate(a1["injected"], a0["injected"]),
            "replayed": rate(a1["replayed"], a0["replayed"]),
            "attacker": {k: a1[k] for k in ("connected", "detail", "identity", "enabled",
                                            "captured")},
        }

    def state(self, since: float = 0.0) -> dict:
        with self.lock:
            return {"config": copy.deepcopy(self.config),
                    "startup_only": [f"{s}.{k}" for s, k in sorted(STARTUP_ONLY)],
                    "history": [p for p in self.history if p["t"] > since],
                    "events": list(self.events),
                    "agents": self.cluster.snapshot() if self.cluster else []}

    def measure(self, settle: float, duration: float) -> dict:
        """One matrix cell: wait for the change to settle, then measure a window."""
        time.sleep(settle)
        self.gateway.reset()
        f0, a0 = self.fleet.poll(), self.attacker.poll()
        b0, pid0, t0 = self.broker.cpu_seconds(), self.broker.proc.pid, time.time()
        time.sleep(duration)
        summary = self.gateway.summary()
        f1, a1 = self.fleet.poll(), self.attacker.poll()
        b1, pid1, t1 = self.broker.cpu_seconds(), self.broker.proc.pid, time.time()
        sent = f1["sent"] - f0["sent"]
        received = summary["received"]

        def share(part: float) -> float:
            # Sensors report every 0.5 s, so window edges are fuzzy by up to that
            # much: shares are accurate to roughly ±0.5 s / duration.
            return round(min(max(100.0 * part / sent, 0.0), 100.0), 1) if sent else 0.0

        return {
            "sent_msg_s": round(sent / (t1 - t0)),
            "delivered_msg_s": round(summary["msg_per_s"]),
            "loss_pct": share(sent - received),
            "rejected": summary["rejected"],
            "leak_pct": share(a1["received"] - a0["received"]),
            "forged_ok": summary["forged_accepted"],
            "replays_ok": summary["replays_accepted"],
            "lat_p50_us": round(summary["latency_us"]["p50"]),
            "lat_p99_us": round(summary["latency_us"]["p99"]),
            "gw_cpu_pct": summary["cpu_pct"],
            "gw_cpu_us_per_msg": summary["cpu_us_per_msg"],
            "broker_cpu_pct": round(100.0 * (b1 - b0) / (t1 - t0), 1) if pid0 == pid1 else "",
            "sensors_up": f1["up"],
            "attacker": a1["detail"],
        }
