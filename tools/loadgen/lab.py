"""The load lab: broker + gateway + sensors + attacker, all driven by one config
in which every security feature can be switched, at startup or while running.

    [transport]  mode plain|tls|mtls, tls_version, protocol 3.1.1|5, auth, acl,
                 clientid_binding, sys_topics, max_packet, max_connections
                                                          broker + every client
    [payload]    protection none|auth_only|encrypt|sign, freshness, replay,
                 key_binding, rate_limit, key_epoch       gateway + sensors
    [storage]    persistence none|plain|at-rest           gateway
    [downlink]   rate: gateway → actuator commands/s      gateway + sensors
    [response]   revoked: sensors whose credentials are withdrawn everywhere
    [load]       rate, payload, zone (live); sensors, processes, qos (startup)
    [attacker]   enabled, impersonate, inject_rate, replay_rate
    [cluster]    sensor_agents, attacker_agents: run those on other machines
                 (see cluster.py / agent.py); 0 = run them on this machine

Lab.apply() takes a partial config, validates it and performs exactly the
actions each change needs (reload, restart + reconnect, or a pipeline switch).
A sampler records one metrics point per second for the dashboard and matrix.

Key rotation (payload.key_epoch, may only increase): new keys for every
device are installed next to the old ones, senders switch, and after a grace
period the old keys are revoked, so whatever was captured or stolen with them
stops working. Revocation (response.revoked, may only grow): the sensor's
payload keys leave the gateway, its password leaves the broker and, with mtls,
its certificate goes on the CRL. A revoked device must be re-enrolled, which
this lab does not do: restart the lab to undo it.
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

ROTATION_GRACE_S = 3.0

DEFAULTS: dict = {
    "broker": {"host": "127.0.0.1", "port": 18830, "advertise": ""},
    "transport": {"mode": "plain", "tls_version": "1.2", "protocol": "3.1.1", "auth": False,
                  "acl": True, "clientid_binding": False, "sys_topics": False, "max_packet": 0,
                  "max_connections": 0},
    "payload": {"protection": "encrypt", "freshness": True, "replay": True, "key_binding": True,
                "rate_limit": 0, "key_epoch": 0},
    "storage": {"persistence": "none"},
    "downlink": {"rate": 0},
    "response": {"revoked": ""},
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
    "transport": {"mode": ("plain", "tls", "mtls"), "tls_version": ("1.2", "1.3"),
                  "protocol": ("3.1.1", "5"), "auth": bool, "acl": bool,
                  "clientid_binding": bool, "sys_topics": bool, "max_packet": int,
                  "max_connections": int},
    "payload": {"protection": ("none", "auth_only", "encrypt", "sign"), "freshness": bool,
                "replay": bool, "key_binding": bool, "rate_limit": int, "key_epoch": int},
    "storage": {"persistence": ("none", "plain", "at-rest")},
    "downlink": {"rate": int},
    "response": {"revoked": str},
    "load": {"sensors": int, "rate": float, "payload": int, "zone": ("open", "restricted"),
             "qos": (0, 1, 2), "processes": int},
    "attacker": {"enabled": bool, "impersonate": bool, "inject_rate": float,
                 "replay_rate": float},
    "cluster": {"listen": str, "port": int, "sensor_agents": int, "attacker_agents": int,
                "join_timeout": float},
}

STARTUP_ONLY = {("broker", "host"), ("broker", "port"), ("broker", "advertise"),
                ("load", "sensors"), ("load", "processes"), ("load", "qos")} | {
                ("cluster", k) for k in SPEC["cluster"]}
BROKER_KEYS = ("mode", "tls_version", "auth", "acl", "clientid_binding", "sys_topics",
               "max_packet", "max_connections")
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


def parse_revoked(text: str) -> set[int]:
    """'3, 7' -> {3, 7}."""
    out = set()
    for part in str(text).replace(" ", "").split(","):
        if part:
            if not part.isdigit() or int(part) < 1:
                raise ValueError(f"response.revoked: {part!r} is not a sensor number")
            out.add(int(part))
    return out


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
                # TOML/JSON may give "5" or 5, 1.3 or "1.3": compare as text.
                match = [c for c in rule if str(c) == str(value)]
                if not match:
                    raise ValueError(f"{section}.{key} must be one of {', '.join(map(str, rule))}")
                value = match[0]
            elif rule is float:
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    raise ValueError(f"{section}.{key} must be a non-negative number")
                value = float(value)
            elif rule is int:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"{section}.{key} must be a non-negative integer")
            elif rule is str and not isinstance(value, str):
                value = str(value)
            elif not isinstance(value, rule):
                raise ValueError(f"{section}.{key} must be {rule.__name__}")
            changes.append((section, key, value))
    return changes


def merged(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for section, key, value in validate(patch):
        out[section][key] = value
    revoked = parse_revoked(out["response"]["revoked"])
    out["response"]["revoked"] = ",".join(map(str, sorted(revoked)))
    if any(n > out["load"]["sensors"] for n in revoked):
        raise ValueError("response.revoked names a sensor that does not exist")
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
    fmt = lambda v: ("on" if v else "off") if isinstance(v, bool) else (str(v) or "none")  # noqa: E731
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
                "ca": str(self.pki.ca), "protocol": t["protocol"]}

    def broker_settings(self) -> dict:
        t = self.config["transport"]
        revoked = parse_revoked(self.config["response"]["revoked"])
        return {**{k: t[k] for k in BROKER_KEYS},
                "revoked": frozenset(pki_module.owner(n) for n in revoked)}

    def start(self) -> None:
        c = self.config
        n_sensors, cl = c["load"]["sensors"], c["cluster"]
        self.advertise = advertised_host(c)
        self.sensor_ids = list(range(1, n_sensors + 1))
        if c["payload"]["key_epoch"] != 0 or c["response"]["revoked"]:
            raise ValueError("payload.key_epoch and response.revoked can only change while "
                             "the lab runs")

        # Reserve agents first: nothing else is worth starting until they are here.
        sensor_agents = attacker_agents = []
        if uses_agents(c):
            self.log(f"agents join with:\n  {self.cluster.join_command(self.cluster_address())}")
            sensor_agents = self._claim("sensors", cl["sensor_agents"])
            attacker_agents = self._claim("attacker", cl["attacker_agents"])
        local_ids = [] if sensor_agents else self.sensor_ids
        self.ca = (self.cluster.identity.ca if self.cluster
                   else pki_module.CertificateAuthority.create())

        self.log(f"credentials for {n_sensors} sensors in {self.workdir}")
        self.pki, self.keys = pki_module.generate(self.workdir, self.ca, self.sensor_ids,
                                                  local_ids, server_names=[self.advertise])
        self.passwords = pki_module.read_credentials(self.pki.credentials)
        self.broker = Broker(self.workdir, self.pki, c["broker"]["host"], c["broker"]["port"])
        self.broker.start(**self.broker_settings())
        self.gateway = GatewayProcess(self.gateway_binary, self.pki, self.advertise,
                                      c["broker"]["port"], c, self.verbose)

        p = c["payload"]
        settings = {"transport": self.transport(), "protection": p["protection"],
                    "freshness": p["freshness"], "replay": p["replay"],
                    "rate": c["load"]["rate"], "payload": c["load"]["payload"],
                    "zone": c["load"]["zone"], "qos": c["load"]["qos"]}
        if sensor_agents:
            slices = [self.sensor_ids[i::len(sensor_agents)] for i in range(len(sensor_agents))]
            members = []
            for agent, ids in zip(sensor_agents, slices):
                self.log(f"provisioning {len(ids)} sensors on {agent.host}")
                members.append(RemoteSensors(
                    agent, ids, self.ca, self.passwords,
                    pki_module.device_view(self.keys, ids).lines(), settings,
                    record_issued=self.pki.record_issued))
            self.fleet = FleetGroup(members, [a.host for a in sensor_agents])
        else:
            self.fleet = FleetGroup([SensorFleet(
                local_ids, c["load"]["processes"], keys_file=str(self.pki.device_keys),
                credentials=self.passwords, clients_dir=str(self.pki.clients_dir),
                **settings)], ["local"])

        attack = {"transport": self.transport(), "zone": c["load"]["zone"], **c["attacker"]}
        if attacker_agents:
            self.attacker = AttackerGroup([RemoteAttacker(a, self.ca, attack)
                                           for a in attacker_agents],
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
            for s, k, old, value in changed:
                if (s, k) in STARTUP_ONLY:
                    raise ValueError(f"{s}.{k} can only be set at startup")
                if (s, k) == ("payload", "key_epoch") and value < old:
                    raise ValueError("payload.key_epoch can only increase (key ids are never "
                                     "reused)")
                if (s, k) == ("response", "revoked") and not (
                        parse_revoked(old) <= parse_revoked(value)):
                    raise ValueError("revocation is permanent for this run (a revoked device "
                                     "must be re-enrolled): restart the lab to undo it")
            if not changed:
                return []
            keys = {(s, k) for s, k, _, _ in changed}
            old_config, self.config = self.config, new
            t, p = new["transport"], new["payload"]

            if ("response", "revoked") in keys:
                self._revoke(parse_revoked(new["response"]["revoked"]) -
                             parse_revoked(old_config["response"]["revoked"]))
            broker_change = {k: t[k] for s, k in keys if s == "transport" and k in BROKER_KEYS}
            if broker_change or ("response", "revoked") in keys:
                action = self.broker.apply(**self.broker_settings())
                if action == "restart" or ("transport", "mode") in keys:
                    self.gateway.set("transport", t["mode"])
                    self.gateway.reconnect()
                if ("transport", "mode") in keys:
                    self.fleet.update(transport=self.transport())
                    self.attacker.update(transport=self.transport())
            if ("transport", "protocol") in keys:
                self.gateway.set("protocol", t["protocol"])
                self.gateway.reconnect()
                self.fleet.update(transport=self.transport())
                self.attacker.update(transport=self.transport())
            if ("payload", "protection") in keys:
                self.gateway.set("protection", p["protection"])
                self.fleet.update(protection=p["protection"])
            for key in ("freshness", "replay"):
                if ("payload", key) in keys:
                    self.gateway.set(key, p[key])
                    self.fleet.update(**{key: p[key]})
            if ("payload", "key_binding") in keys:
                self.gateway.set("key_binding", p["key_binding"])
            if ("payload", "rate_limit") in keys:
                self.gateway.set("rate_limit", p["rate_limit"])
            if ("payload", "key_epoch") in keys:
                self._rotate(old_config["payload"]["key_epoch"], p["key_epoch"])
            if ("storage", "persistence") in keys:
                self.gateway.set("persistence", new["storage"]["persistence"])
            if ("downlink", "rate") in keys:
                self.gateway.set("downlink", new["downlink"]["rate"])
            load = {k: new["load"][k] for s, k in keys if s == "load"}
            if load:
                self.fleet.update(**load)
                if "zone" in load:
                    self.attacker.update(zone=load["zone"])
                    self.gateway.set("zone", load["zone"])
            attack = {k: new["attacker"][k] for s, k in keys if s == "attacker"}
            if attack:
                self.attacker.update(**attack)

            descriptions = [describe(*c) for c in changed]
            for d in descriptions:
                self._event(d)
            return descriptions

    def _active_sensors(self) -> list[int]:
        revoked = parse_revoked(self.config["response"]["revoked"])
        return [n for n in self.sensor_ids if n not in revoked]

    def _rotate(self, old_epoch: int, epoch: int) -> None:
        """New keys for every device that is not revoked; the old ones die after a grace period."""
        fresh = pki_module.make_keys(self._active_sensors(), epoch)
        self.keys.merge(fresh)
        for line in pki_module.gateway_view(fresh).lines():
            self.gateway.add_key(line)
        self.fleet.rotate(fresh, epoch)
        self.gateway.set("sending_key", pki_module.key_id(pki_module.GATEWAY, epoch))
        old_ids = [kid for kid in self.keys.owners if kid // pki_module.EPOCH_STRIDE == old_epoch]

        def retire() -> None:
            if self._stop.wait(ROTATION_GRACE_S):
                return
            with self.lock:
                for kid in old_ids:
                    self.gateway.revoke_key(kid)
                    self.keys.remove(kid)
                self.fleet.update(drop_keys=old_ids)
                self._event(f"keys of epoch {old_epoch} revoked ({len(old_ids)} keys)")

        threading.Thread(target=retire, daemon=True).start()

    def _revoke(self, sensors: set[int]) -> None:
        names = {pki_module.owner(n) for n in sensors}
        for kid, name in list(self.keys.owners.items()):
            if name in names:
                self.gateway.revoke_key(kid)
                self.keys.remove(kid)
        revoked = {pki_module.owner(n) for n in parse_revoked(self.config["response"]["revoked"])}
        pki_module.write_passwd(self.pki, self.passwords, revoked)
        pki_module.write_crl(self.pki, self.ca, revoked)

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
        cmd_reasons = set(f1.get("cmd_rejected_by", {})) | set(f0.get("cmd_rejected_by", {}))
        same_broker = prev["broker_pid"] == cur["broker_pid"]
        return {
            "t": cur["t"],
            "sent": rate(f1["sent"], f0["sent"]),
            "skipped": rate(f1["skipped"], f0["skipped"]),
            "kicked": rate(g(f1, "kicked"), g(f0, "kicked")),
            "sensors_up": f1["up"], "sensors_total": f1["total"],
            "sensor_error": f1["last_error"],
            "gw_connected": bool(g1.get("connected")),
            "delivered": rate(g(g1, "delivered"), g(g0, "delivered")),
            "rejected": rate(g(g1, "rejected"), g(g0, "rejected")),
            "rejected_by": {r: rate(g1.get("rejected_by", {}).get(r, 0),
                                    g0.get("rejected_by", {}).get(r, 0)) for r in reasons},
            "forged_ok": rate(g(g1, "forged_accepted"), g(g0, "forged_accepted")),
            "replays_ok": rate(g(g1, "replays_accepted"), g(g0, "replays_accepted")),
            "dup_rejected": rate(g(g1, "duplicates_rejected"), g(g0, "duplicates_rejected")),
            "cmd_sent": rate(g(g1, "commands_sent"), g(g0, "commands_sent")),
            "cmd_ok": rate(g(f1, "cmd_ok"), g(f0, "cmd_ok")),
            "cmd_rejected": rate(g(f1, "cmd_rejected"), g(f0, "cmd_rejected")),
            "cmd_rejected_by": {r: rate(f1.get("cmd_rejected_by", {}).get(r, 0),
                                        f0.get("cmd_rejected_by", {}).get(r, 0))
                                for r in cmd_reasons},
            "cmd_forged_ok": rate(g(f1, "cmd_forged_ok"), g(f0, "cmd_forged_ok")),
            "cmd_replay_ok": rate(g(f1, "cmd_replay_ok"), g(f0, "cmd_replay_ok")),
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

        def delta(key: str) -> int:
            return f1.get(key, 0) - f0.get(key, 0)

        rejected_by = summary.get("rejected_by", {})
        return {
            "sent_msg_s": round(sent / (t1 - t0)),
            "delivered_msg_s": round(summary["msg_per_s"]),
            "loss_pct": share(sent - received),
            "rejected": summary["rejected"],
            "rejected_by": " ".join(f"{k}={v}" for k, v in sorted(rejected_by.items())),
            "rate_limited": rejected_by.get("RateLimited", 0),
            "leak_pct": share(a1["received"] - a0["received"]),
            "forged_ok": summary["forged_accepted"],
            "replays_ok": summary["replays_accepted"],
            "cmd_sent": summary.get("commands_sent", 0),
            "cmd_ok": delta("cmd_ok"),
            "cmd_rejected": delta("cmd_rejected"),
            "kicked": delta("kicked"),
            "lat_p50_us": round(summary["latency_us"]["p50"]),
            "lat_p99_us": round(summary["latency_us"]["p99"]),
            "gw_cpu_pct": summary["cpu_pct"],
            "gw_cpu_us_per_msg": summary["cpu_us_per_msg"],
            "broker_cpu_pct": round(100.0 * (b1 - b0) / (t1 - t0), 1) if pid0 == pid1 else "",
            "sensors_up": f1["up"],
            "attacker_connected": bool(a1.get("connected")),
            "attacker": a1["detail"],
        }
