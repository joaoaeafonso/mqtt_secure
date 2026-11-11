"""The load lab: broker + gateway + sensors + attacker, all driven by one config
in which every security feature can be switched, at startup or while running.

    [transport]  mode plain|tls|mtls, tls_version, protocol 3.1.1|5, auth, acl,
                 clientid_binding, sys_topics, max_packet, max_connections
                                                          broker + every client
    [payload]    protection none|auth_only|encrypt|sign, cipher aes-256-gcm|
                 chacha20-poly1305, accept, freshness, replay, key_binding,
                 rate_limit, key_epoch                    gateway + sensors
    [storage]    persistence none|plain|at-rest           gateway
    [downlink]   rate: gateway → actuator commands/s      gateway + sensors
    [response]   revoked: sensors whose credentials are withdrawn everywhere
    [load]       rate, payload, zone (live); sensors, processes, qos (startup)
    [attacker]   enabled, impersonate, inject_rate, replay_rate, republish_rate,
                 relabel_rate, stolen_key (+ stolen_*; the real device is silent
                 while compromised unless stolen_exclusive = false), forge_commands_rate,
                 slow_connections, probe_rate; wiretap (startup), tamper
    [cluster]    sensor_agents, attacker_agents: run those on other machines
                 (see cluster.py / agent.py); 0 = run them on this machine

Lab.apply() takes a partial config, validates it and performs exactly the
actions each change needs (reload, restart + reconnect, or a pipeline switch).
A sampler records one metrics point per second for the dashboard and matrix.

Dependencies are validated, not assumed: freshness, replay and key_binding
check the envelope, so they cannot be on with protection = none (the gateway
refuses the same combination).

The AEAD algorithm (payload.cipher) is an attribute of the keys, so changing
it is a key rotation: the next epoch's keys use the new algorithm.

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
from dataclasses import dataclass
from pathlib import Path

import keylog
import pki as pki_module
import procstats
from attacker import Attacker
from broker import Broker
from cluster import (AttackerGroup, ControlServer, FleetGroup, RemoteAttacker, RemoteSensors,
                     primary_address)
from gateway import GatewayProcess
from msec_envelope import AEAD_ALGORITHMS, AES_GCM, CHACHA20
from relay import TAMPER_MODES, Relay
from sensors import SensorFleet

ROTATION_GRACE_S = 3.0

# No defence at all: security level K0. Every defence is something to turn on.
DEFAULTS: dict = {
    "broker": {"host": "127.0.0.1", "port": 18830, "advertise": ""},
    "transport": {"mode": "plain", "tls_version": "1.3", "protocol": "5", "auth": False,
                  "acl": False, "clientid_binding": False, "sys_topics": False, "max_packet": 0,
                  "max_connections": 0},
    "payload": {"protection": "none", "cipher": AES_GCM, "accept": "", "freshness": False,
                "replay": False, "key_binding": False, "rate_limit": 0, "key_epoch": 0},
    "storage": {"persistence": "none"},
    "downlink": {"rate": 0},
    "response": {"revoked": ""},
    "load": {"sensors": 50, "rate": 20.0, "payload": 64, "zone": "restricted", "qos": 0,
             "processes": 2},
    "attacker": {"enabled": True, "impersonate": False, "inject_rate": 0.0,
                 "replay_rate": 0.0, "republish_rate": 0.0, "relabel_rate": 0.0,
                 "stolen_key": 0, "stolen_exclusive": True, "stolen_rate": 0.0,
                 "stolen_target": "own",
                 "stolen_mode": "", "stolen_age_s": 0.0, "forge_commands_rate": 0.0,
                 "slow_connections": 0, "probe_rate": 0.0,
                 "wiretap": False, "tamper": "none", "tamper_delay_s": 2.0},
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
    "payload": {"protection": ("none", "auth_only", "encrypt", "sign"),
                "cipher": tuple(AEAD_ALGORITHMS), "accept": str, "freshness": bool,
                "replay": bool, "key_binding": bool, "rate_limit": int, "key_epoch": int},
    "storage": {"persistence": ("none", "plain", "at-rest")},
    "downlink": {"rate": int},
    "response": {"revoked": str},
    "load": {"sensors": int, "rate": float, "payload": int, "zone": ("open", "restricted"),
             "qos": (0, 1, 2), "processes": int},
    "attacker": {"enabled": bool, "impersonate": bool, "inject_rate": float,
                 "replay_rate": float, "republish_rate": float, "relabel_rate": float,
                 "stolen_key": int, "stolen_exclusive": bool, "stolen_rate": float,
                 "stolen_target": ("own", "other"),
                 "stolen_mode": ("", "auth_only", "encrypt", "sign"), "stolen_age_s": float,
                 "forge_commands_rate": float, "slow_connections": int, "probe_rate": float,
                 "wiretap": bool, "tamper": TAMPER_MODES, "tamper_delay_s": float},
    "cluster": {"listen": str, "port": int, "sensor_agents": int, "attacker_agents": int,
                "join_timeout": float},
}

STARTUP_ONLY = {("broker", "host"), ("broker", "port"), ("broker", "advertise"),
                ("load", "sensors"), ("load", "processes"), ("load", "qos"),
                ("attacker", "wiretap")} | {
                ("cluster", k) for k in SPEC["cluster"]}
BROKER_KEYS = ("mode", "tls_version", "auth", "acl", "clientid_binding", "sys_topics",
               "max_packet", "max_connections")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
# Settings of [attacker] that the lab handles itself (the relay), not the attacker process.
RELAY_KEYS = ("wiretap", "tamper", "tamper_delay_s")
# Also the lab's business: whether the real device keeps running while compromised.
LAB_ATTACK_KEYS = (*RELAY_KEYS, "stolen_exclusive")
ACCEPTABLE = ("auth_only", "encrypt", "sign")
# Room for the envelope (≤ 25 + 12 nonce + 64 signature bytes), the topic and
# the MQTT headers on top of the plaintext.
PACKET_OVERHEAD = 512


@dataclass(frozen=True)
class Level:
    """One configuration of the report's evaluation plan (Section 7, Table 17).

    Each level adds one layer or mechanism to the previous one, so the cost and
    the benefit of every step can be measured on its own. `transport` switches
    the whole broker layer (mTLS 1.3, passwords, ACL, client id = username);
    `limits` switches the gateway rate limit together with the broker's packet
    and connection limits."""
    id: str
    name: str
    adds: str
    transport: bool
    protection: str
    freshness: bool
    replay: bool
    key_binding: bool
    limits: bool
    cipher: str = AES_GCM

    def patch(self, config: dict) -> dict:
        """Limits are derived from the load, so legitimate traffic fits: a
        connection per sensor plus room for the gateway, attackers and
        reconnects; twice each sensor's rate per topic; the largest legitimate
        packet."""
        load, on = config["load"], self.transport
        return {
            "transport": {"mode": "mtls" if on else "plain", "tls_version": "1.3",
                          "protocol": "5", "auth": on, "acl": on, "clientid_binding": on,
                          "sys_topics": False,
                          "max_packet": load["payload"] + PACKET_OVERHEAD if self.limits else 0,
                          "max_connections": load["sensors"] + 16 if self.limits else 0},
            "payload": {"protection": self.protection, "cipher": self.cipher, "accept": "",
                        "freshness": self.freshness,
                        "replay": self.replay, "key_binding": self.key_binding,
                        "rate_limit": max(10, int(load["rate"] * 2) + 1) if self.limits else 0},
            "load": {"zone": "restricted"},
        }

    def matches(self, config: dict) -> bool:
        """True if `config` is this level, whatever the load-derived limits are."""
        t, p = config["transport"], config["payload"]
        on = self.transport
        return (t["mode"] == ("mtls" if on else "plain") and t["auth"] == on
                and t["acl"] == on and t["clientid_binding"] == on
                and (not on or t["tls_version"] == "1.3")
                and p["protection"] == self.protection and p["freshness"] == self.freshness
                and p["replay"] == self.replay and p["key_binding"] == self.key_binding
                and (p["rate_limit"] > 0) == self.limits
                and (t["max_connections"] > 0) == self.limits and not p["accept"]
                and p["cipher"] == self.cipher)


LEVELS: list[Level] = [
    Level("K0", "No protection", "reference, nothing on",
          False, "none", False, False, False, False),
    Level("K1", "Transport", "each hop protected; only known clients reach the broker",
          True, "none", False, False, False, False),
    Level("K2", "+ Authentication", "end-to-end integrity and topic binding (GMAC)",
          True, "auth_only", False, False, False, False),
    Level("K3", "+ Encryption", "confidentiality, also from the broker (AES-256-GCM)",
          True, "encrypt", False, False, False, False),
    Level("K4", "+ Timestamp", "rejects old messages (temporal validity)",
          True, "encrypt", True, False, False, False),
    Level("K5", "+ Replay window", "rejects replayed messages (sequence numbers)",
          True, "encrypt", False, True, False, False),
    Level("K6", "Full envelope", "timestamp check and replay window together",
          True, "encrypt", True, True, False, False),
    Level("K7", "+ Key–topic", "a stolen key only publishes on its owner's topics",
          True, "encrypt", True, True, True, False),
    Level("K8", "+ Rate limit", "floods dropped before any cryptography",
          True, "encrypt", True, True, True, True),
    Level("K9", "Signatures", "proof of origin (Ed25519) instead of AES",
          True, "sign", True, True, True, True),
    Level("K10", "Envelope, no TLS", "K7's envelope over plain TCP: what TLS adds",
          False, "encrypt", True, True, True, False),
    Level("K11", "ChaCha20", "K8 with ChaCha20-Poly1305 (for CPUs without AES hardware)",
          True, "encrypt", True, True, True, True, CHACHA20),
]
LEVEL_BY_ID = {level.id: level for level in LEVELS}


def level_patch(level: Level, config: dict, extra: dict | None = None) -> dict:
    """`level` plus `extra` settings as ONE patch, to apply in one step.

    The level's limits follow the load, so they are derived from the load
    `extra` sets, not from the one in effect: applying the level first and
    e.g. load.payload = 4096 after it would leave (or be refused by) a
    max_packet computed for the old payload. `extra` wins over the level."""
    extra = extra or {}
    preview = copy.deepcopy(config)
    preview["load"].update(extra.get("load", {}))
    out = level.patch(preview)
    for section, values in extra.items():
        out.setdefault(section, {}).update(values)
    return out


def current_level(config: dict) -> str | None:
    return next((level.id for level in LEVELS if level.matches(config)), None)


def hardened(config: dict) -> dict:
    """Every defence on at once: level K9. What remains possible with all of
    this on is listed in the README."""
    return LEVEL_BY_ID["K9"].patch(config)


@dataclass(frozen=True)
class DemoStep:
    """One step of the defence ladder: a DEMONSTRATION order, not an evaluation
    configuration (those are LEVELS, K0–K11, and nothing is measured on these).

    K0–K11 add mechanisms in the order that isolates each one's cost, and K1
    switches the whole broker layer on at once: from then on the outside
    attacker cannot connect and no attack reaches the layers behind it. The
    ladder goes inside out instead: the end-to-end layers first, over plain
    TCP with the attacker on the broker, the perimeter last, and finally the
    perimeter taken away again (the breach), to show the inner layers holding.
    Every step is a full configuration, so any step can be picked from anywhere."""
    id: str
    name: str
    teaches: str
    protection: str = "none"
    freshness: bool = False
    replay: bool = False
    key_binding: bool = False
    rate_limit: bool = False
    acl: bool = False
    auth: bool = False
    mtls: bool = False

    def patch(self, config: dict) -> dict:
        load = config["load"]
        return {
            "transport": {"mode": "mtls" if self.mtls else "plain", "tls_version": "1.3",
                          "protocol": "5", "auth": self.auth, "acl": self.acl,
                          "clientid_binding": self.mtls, "sys_topics": False,
                          "max_packet": 0, "max_connections": 0},
            "payload": {"protection": self.protection, "cipher": AES_GCM, "accept": "",
                        "freshness": self.freshness, "replay": self.replay,
                        "key_binding": self.key_binding,
                        "rate_limit": max(10, int(load["rate"] * 2) + 1) if self.rate_limit else 0},
            "load": {"zone": "restricted"},
        }

    def matches(self, config: dict) -> bool:
        return all(config[section][key] == value
                   for section, values in self.patch(config).items()
                   for key, value in values.items())


_INNER = {"protection": "encrypt", "freshness": True, "replay": True, "key_binding": True,
          "rate_limit": True}
DEMO_STEPS: list[DemoStep] = [
    DemoStep("D0", "Open", "an open broker gives everything away"),
    DemoStep("D1", "+ Authentication",
             "integrity is not confidentiality: forgeries stop, contents are still readable",
             protection="auth_only"),
    DemoStep("D2", "+ Encryption",
             "confidentiality end to end, even from the broker; but an authentic copy is "
             "still authentic", protection="encrypt"),
    DemoStep("D3", "+ Timestamp",
             "nothing changes for a replay: a 60 s validity alone lets recent copies through "
             "(it does stop an old message never seen before)",
             protection="encrypt", freshness=True),
    DemoStep("D4", "+ Replay window", "sequence numbers stop copies",
             protection="encrypt", freshness=True, replay=True),
    DemoStep("D5", "+ Key–topic",
             "nothing changes for an outsider: it contains a compromised device, whose key "
             "now only works on its own topics",
             protection="encrypt", freshness=True, replay=True, key_binding=True),
    DemoStep("D6", "+ Rate limit", "excess traffic is dropped before any work is done",
             **_INNER),
    DemoStep("D7", "+ ACL",
             "an ACL without authentication trusts whatever name a client claims",
             **_INNER, acl=True),
    DemoStep("D8", "+ Passwords", "the perimeter stops the outsider at the door",
             **_INNER, acl=True, auth=True),
    DemoStep("D9", "+ Mutual TLS",
             "each hop encrypted and identity bound to a certificate; the price shows in "
             "the cost tile", **_INNER, acl=True, auth=True, mtls=True),
    DemoStep("D10", "Breach",
             "defence in depth: the broker layer is gone again and the inner layers still hold",
             **_INNER),
]
DEMO_BY_ID = {step.id: step for step in DEMO_STEPS}


def current_demo_step(config: dict, chosen: str | None = None) -> str | None:
    """The step `config` is at. D6 and D10 (the breach) are the same
    configuration reached from different sides: `chosen`, the step last
    picked, decides between them while it still matches."""
    if chosen in DEMO_BY_ID and DEMO_BY_ID[chosen].matches(config):
        return chosen
    return next((s.id for s in DEMO_STEPS if s.matches(config)), None)


PRESETS = {"hardened": hardened, **{level.id: level.patch for level in LEVELS},
           **{step.id: step.patch for step in DEMO_STEPS}}


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


def parse_accept(text: str) -> list[str]:
    """'encrypt, auth_only' -> ['encrypt', 'auth_only'] ('' = the protection mode only)."""
    modes = [m for m in str(text).replace(" ", "").split(",") if m]
    for m in modes:
        if m not in ACCEPTABLE:
            raise ValueError(f"payload.accept: {m!r} is not one of {', '.join(ACCEPTABLE)}")
    return list(dict.fromkeys(modes))


def check_dependencies(config: dict) -> None:
    """Refuses combinations in which a switched-on mechanism could not work."""
    p = config["payload"]
    if p["protection"] == "none":
        on = [k for k in ("freshness", "replay", "key_binding") if p[k]]
        if on:
            raise ValueError(f"payload.{', payload.'.join(on)} need{'' if len(on) > 1 else 's'} "
                             "the envelope: turn "
                             f"{'them' if len(on) > 1 else 'it'} off or set payload.protection")
        if p["accept"]:
            raise ValueError("payload.accept needs the envelope (payload.protection is none)")
    a = config["attacker"]
    if a["stolen_key"] > config["load"]["sensors"]:
        raise ValueError("attacker.stolen_key names a sensor that does not exist")
    needs_device = [k for k in ("stolen_rate", "forge_commands_rate") if a[k] > 0]
    if needs_device and not a["stolen_key"]:
        raise ValueError(f"attacker.{needs_device[0]} needs attacker.stolen_key (a device "
                         "whose material the attacker holds)")
    if a["tamper"] != "none" and not a["wiretap"]:
        raise ValueError("attacker.tamper needs attacker.wiretap = true (set at startup)")


def merged(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for section, key, value in validate(patch):
        out[section][key] = value
    out["payload"]["accept"] = ",".join(parse_accept(out["payload"]["accept"]))
    check_dependencies(out)
    revoked = parse_revoked(out["response"]["revoked"])
    out["response"]["revoked"] = ",".join(map(str, sorted(revoked)))
    if any(n > out["load"]["sensors"] for n in revoked):
        raise ValueError("response.revoked names a sensor that does not exist")
    if out["transport"]["max_packet"] and (
            out["load"]["payload"] + PACKET_OVERHEAD > out["transport"]["max_packet"]):
        raise ValueError(f"transport.max_packet must leave room for the payload: at least "
                         f"load.payload + {PACKET_OVERHEAD} = "
                         f"{out['load']['payload'] + PACKET_OVERHEAD} bytes")
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
        self.listeners: list = []  # called with the text of every event (e.g. Capture.mark)
        self._stop = threading.Event()
        # Lab time: the wall clock at start plus monotonic time since. The wall
        # clock itself can step (NTP; WSL2 steps back seconds at a time), which
        # would give negative or inflated intervals and points out of order.
        self._wall0, self._mono0 = time.time(), time.monotonic()
        self.broker = self.gateway = self.fleet = self.attacker = self.relay = None
        self.demo_step: str | None = None  # the demo step last picked (see current_demo_step)
        self.sensor_agents: list = []

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
        self.sensor_agents = sensor_agents
        local_ids = [] if sensor_agents else self.sensor_ids
        self.ca = (self.cluster.identity.ca if self.cluster
                   else pki_module.CertificateAuthority.create())

        self.log(f"credentials for {n_sensors} sensors in {self.workdir}")
        self.pki, self.keys = pki_module.generate(self.workdir, self.ca, self.sensor_ids,
                                                  local_ids, server_names=[self.advertise],
                                                  algorithm=c["payload"]["cipher"])
        self.passwords = pki_module.read_credentials(self.pki.credentials)
        self.broker = Broker(self.workdir, self.pki, c["broker"]["host"], c["broker"]["port"],
                             keylog.library_for(self.gateway_binary))
        self.broker.start(**self.broker_settings())
        gateway_host, gateway_port = self.advertise, c["broker"]["port"]
        if c["attacker"]["wiretap"]:
            # The gateway's link runs through an attacker-controlled relay.
            self.relay = Relay(self.broker.probe_host, c["broker"]["port"], log=self.log)
            self.relay.configure(c["attacker"]["tamper"], c["attacker"]["tamper_delay_s"])
            gateway_host, gateway_port = "127.0.0.1", self.relay.port
        self.gateway_port = gateway_port
        self.gateway = GatewayProcess(self.gateway_binary, self.pki, gateway_host,
                                      gateway_port, c, self.verbose)

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

        if self.silenced_sensors():
            self.fleet.update(silenced=self.silenced_sensors())
        attack = self.attacker_settings()
        if attacker_agents:
            self.attacker = AttackerGroup([RemoteAttacker(a, self.ca, attack)
                                           for a in attacker_agents],
                                          [a.host for a in attacker_agents])
        else:
            self.attacker = AttackerGroup([Attacker(**attack)], ["local"])
        self._event("lab started")
        threading.Thread(target=self._sampler, daemon=True).start()

    def attacker_settings(self) -> dict:
        """What the attacker process gets: its settings, the transport, and, only
        if it has compromised a device, that device's material."""
        c = self.config
        return {"transport": self.transport(), "zone": c["load"]["zone"],
                "protection": c["payload"]["protection"],
                **{k: v for k, v in c["attacker"].items() if k not in LAB_ATTACK_KEYS},
                "material": self.stolen_material()}

    def silenced_sensors(self) -> list[int]:
        """The device the attacker has taken over does not run next to it
        (attacker.stolen_exclusive, the default). Otherwise both use the
        device's client id and take the MQTT session from each other about
        once a second: the attacker is then online only a few percent of the
        time, which turns every compromised-device attack (the flood above
        all) into a trickle and the measurement into a session fight."""
        a = self.config["attacker"]
        on = a["enabled"] and a["stolen_key"] and a["stolen_exclusive"]
        return [a["stolen_key"]] if on else []

    def stolen_material(self) -> dict:
        """sensor-n's secrets: its payload keys (with the gateway's aead and public
        key every actuator holds), its broker password and, with mtls, its
        certificate. Empty unless attacker.stolen_key = n."""
        n = self.config["attacker"]["stolen_key"]
        if not n:
            return {}
        name = pki_module.owner(n)
        out = {"keys": pki_module.device_view(self.keys, [n]).lines(),
               "password": self.passwords.get(name)}
        cert, key = self.pki.client_cert(name), self.pki.client_key(name)
        if cert.exists() and key.exists():
            out.update(cert=cert.read_text(), key=key.read_text())
        return out

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
        for part in (self.attacker, self.fleet, self.gateway, self.relay, self.broker):
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
            old_p, new_p = self.config["payload"], new["payload"]
            if new_p["cipher"] != old_p["cipher"] and new_p["key_epoch"] == old_p["key_epoch"]:
                # The algorithm belongs to the keys: switching it is a rotation.
                new_p["key_epoch"] = old_p["key_epoch"] + 1
                changed.append(("payload", "key_epoch", old_p["key_epoch"], new_p["key_epoch"]))
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
            # Applied in one step: the gateway validates them together, so going
            # e.g. from K6 to K1 never passes through "protection none, freshness on".
            gateway_change = {k: p[k] for k in ("protection", "accept", "freshness", "replay",
                                                "key_binding") if ("payload", k) in keys}
            self.gateway.apply(**gateway_change)
            if ("payload", "protection") in keys:
                self.fleet.update(protection=p["protection"])
                self.attacker.update(protection=p["protection"])
            for key in ("freshness", "replay"):
                if ("payload", key) in keys:
                    self.fleet.update(**{key: p[key]})
            if ("payload", "rate_limit") in keys:
                self.gateway.set("rate_limit", p["rate_limit"])
            if ("payload", "key_epoch") in keys:
                self._rotate(old_config["payload"]["key_epoch"], p["key_epoch"], p["cipher"])
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
            if keys & {("attacker", "stolen_key"), ("attacker", "stolen_exclusive"),
                       ("attacker", "enabled")}:
                # Before the attacker connects as the device (and after it left).
                self.fleet.update(silenced=self.silenced_sensors())
            attack = {k: new["attacker"][k] for s, k in keys
                      if s == "attacker" and k not in LAB_ATTACK_KEYS}
            if ("attacker", "stolen_key") in keys or ("payload", "key_epoch") in keys:
                attack["material"] = self.stolen_material()
            if attack:
                self.attacker.update(**attack)
            if self.relay is not None and keys & {("attacker", "tamper"),
                                                   ("attacker", "tamper_delay_s")}:
                self.relay.configure(new["attacker"]["tamper"], new["attacker"]["tamper_delay_s"])

            descriptions = [describe(*c) for c in changed]
            for d in descriptions:
                self._event(d)
            return descriptions

    def apply_preset(self, name: str) -> list[str]:
        if name not in PRESETS:
            raise ValueError(f"unknown preset {name!r} (known: {', '.join(PRESETS)})")
        with self.lock:
            changes = self.apply(PRESETS[name](self.config))
            self.demo_step = name if name in DEMO_BY_ID else None
            level, step = LEVEL_BY_ID.get(name), DEMO_BY_ID.get(name)
            self._event(f"security level {level.id} — {level.name}" if level
                        else f"demo step {step.id} — {step.name}" if step
                        else f"preset {name}")
            return changes

    def _active_sensors(self) -> list[int]:
        revoked = parse_revoked(self.config["response"]["revoked"])
        return [n for n in self.sensor_ids if n not in revoked]

    def _rotate(self, old_epoch: int, epoch: int, algorithm: str = AES_GCM) -> None:
        """New keys for every device that is not revoked; the old ones die after a grace period."""
        fresh = pki_module.make_keys(self._active_sensors(), epoch, algorithm)
        self.keys.merge(fresh)
        for line in pki_module.gateway_view(fresh).lines():
            self.gateway.add_key(line)
        # Senders switch only once the gateway holds the new keys: a message
        # under a key id it does not know yet fails authentication by design.
        self.gateway.sync()
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

    def now(self) -> float:
        """Seconds since the epoch that never go backwards (see __init__)."""
        return self._wall0 + (time.monotonic() - self._mono0)

    def _event(self, text: str) -> None:
        self.events.append({"t": self.now(), "text": text})
        for listener in self.listeners:
            listener(text)
        self.log(f"· {text}")

    def mark(self, text: str) -> None:
        """Records an event that is not a configuration change (e.g. a scenario start)."""
        self._event(text)

    # --------------------------------------------------------------- metrics ---

    def _sampler(self) -> None:
        prev, waited = None, False
        while not self._stop.wait(1.0):
            gateway = dict(self.gateway.latest)
            stale = prev is not None and gateway.get("_seq") == prev["gateway"].get("_seq")
            if stale and not waited:
                # No new report from the gateway (it reports every ≈ 1.01 s, we
                # sample every 1.00 s): wait one tick for the next one instead
                # of recording a second with nothing delivered. If it is still
                # missing then, the gateway really is silent: record that.
                waited = True
                continue
            waited = False
            raw = {
                "t": self.now(),
                "fleet": self.fleet.poll(),
                "gateway": gateway,
                "attacker": self.attacker.poll(),
                "broker_cpu_s": self.broker.cpu_seconds(),
                "broker_pid": self.broker.proc.pid,
            }
            if prev is not None:
                self.history.append(self._point(prev, raw))
            prev = raw

    @staticmethod
    def _point(prev: dict, cur: dict) -> dict:
        dt = max(cur["t"] - prev["t"], 1e-3)

        def rate(new, old, over=dt):
            # Counters restart from 0 on a gateway `reset` or a broker restart.
            return max(new - old if new >= old else new, 0) / over

        f0, f1 = prev["fleet"], cur["fleet"]
        g0, g1 = prev["gateway"], cur["gateway"]
        a0, a1 = prev["attacker"], cur["attacker"]
        g = lambda d, k: d.get(k, 0)  # noqa: E731
        # The gateway's counters cover the time between ITS reports, not ours.
        gdt = max(g1.get("_mono", 0.0) - g0.get("_mono", 0.0), 1e-3) if "_mono" in g0 else dt
        grate = lambda new, old: rate(new, old, gdt)  # noqa: E731
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
            "delivered": grate(g(g1, "delivered"), g(g0, "delivered")),
            "rejected": grate(g(g1, "rejected"), g(g0, "rejected")),
            "rejected_by": {r: grate(g1.get("rejected_by", {}).get(r, 0),
                                    g0.get("rejected_by", {}).get(r, 0)) for r in reasons},
            "forged_ok": grate(g(g1, "forged_accepted"), g(g0, "forged_accepted")),
            "replays_ok": grate(g(g1, "replays_accepted"), g(g0, "replays_accepted")),
            "dup_rejected": grate(g(g1, "duplicates_rejected"), g(g0, "duplicates_rejected")),
            "cmd_sent": grate(g(g1, "commands_sent"), g(g0, "commands_sent")),
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
            "stolen_sent": rate(g(a1, "stolen_sent"), g(a0, "stolen_sent")),
            "commands_forged": rate(g(a1, "commands_forged"), g(a0, "commands_forged")),
            "attacker": {k: a1[k] for k in ("connected", "detail", "identity", "enabled",
                                            "captured")},
        }

    def state(self, since: float = 0.0) -> dict:
        with self.lock:
            return {"config": copy.deepcopy(self.config),
                    "level": current_level(self.config),
                    "levels": [{"id": lv.id, "name": lv.name, "adds": lv.adds}
                               for lv in LEVELS],
                    "demo_step": current_demo_step(self.config, self.demo_step),
                    "demo_steps": [{"id": s.id, "name": s.name, "teaches": s.teaches}
                                   for s in DEMO_STEPS],
                    "startup_only": [f"{s}.{k}" for s, k in sorted(STARTUP_ONLY)],
                    "history": [p for p in self.history if p["t"] > since],
                    "events": list(self.events),
                    "agents": self.cluster.snapshot() if self.cluster else []}

    def topic_length(self) -> float:
        """Mean length of the sensors' topics (<zone>/sensors/sensor-<n>/temp)."""
        zone = self.config["load"]["zone"]
        return sum(len(f"{zone}/sensors/sensor-{n}/temp") for n in self.sensor_ids) / len(
            self.sensor_ids)

    def measure(self, settle: float, duration: float, connect_test: int = 0) -> dict:
        """One matrix cell: wait for the change to settle, then measure a window.

        Besides throughput, loss, latency and CPU: peak resident memory of the
        gateway and the broker in the window, octets per message on the
        gateway's socket split into payload / envelope / MQTT / TLS and other,
        and (connect_test > 0, after the window) the time and CPU of that many
        gateway reconnections (TLS handshake + CONNECT)."""
        time.sleep(settle)
        f0 = self.fleet.fresh_poll()
        self.gateway.reset()  # right after the fleet's counters: the same window edge
        a0 = self.attacker.poll()
        r0 = self.relay.snapshot() if self.relay else {}
        tcp0 = procstats.tcp_bytes(self.gateway.pid, self.gateway_port)
        rss = procstats.RssSampler({"gateway": self.gateway.pid, "broker": self.broker.proc.pid})
        b0, pid0, t0 = self.broker.cpu_seconds(), self.broker.proc.pid, time.monotonic()
        time.sleep(duration)
        f1 = self.fleet.fresh_poll()
        summary = self.gateway.summary()
        a1 = self.attacker.poll()
        b1, pid1, t1 = self.broker.cpu_seconds(), self.broker.proc.pid, time.monotonic()
        tcp1 = procstats.tcp_bytes(self.gateway.pid, self.gateway_port)
        peaks = rss.stop()
        r1 = self.relay.snapshot() if self.relay else {}
        sent = f1["sent"] - f0["sent"]
        received = summary["received"]

        def share(part: float, of: float = sent) -> float:
            # Sensors report on demand at both edges (fresh_poll), local ones
            # and those on agents alike, so the shares are exact up to the
            # control channel's delay. The attacker reports every 0.5 s:
            # leak_pct is accurate to roughly ±0.5 s / duration.
            return round(min(max(100.0 * part / of, 0.0), 100.0), 1) if of else 0.0

        def delta(key: str) -> int:
            return f1.get(key, 0) - f0.get(key, 0)

        def attack(key: str) -> int:
            return a1.get(key, 0) - a0.get(key, 0)

        def relay(key: str) -> int:
            return r1.get(key, 0) - r0.get(key, 0)

        rejected_by = summary.get("rejected_by", {})
        c = self.config
        wire = (tcp1["received"] - tcp0["received"]) / received if received else None
        bytes_split = procstats.wire_breakdown(
            c["load"]["payload"], c["payload"]["protection"], self.topic_length(),
            c["load"]["qos"], c["transport"]["protocol"], wire if wire and wire > 0 else None)
        result = {
            "sent_msg_s": round(sent / (t1 - t0)),
            "delivered_msg_s": round(summary["msg_per_s"]),
            "loss_pct": share(sent - received),
            "rejected": summary["rejected"],
            "rejected_by": " ".join(f"{k}={v}" for k, v in sorted(rejected_by.items())),
            "rate_limited": rejected_by.get("RateLimited", 0),
            "leak_pct": share(attack("received")),
            "leak_readable_pct": share(attack("readable")),
            "forged_ok": summary["forged_accepted"],
            "replays_ok": summary["replays_accepted"],
            "republished_ok": summary.get("republished_accepted", 0),
            "cmd_sent": summary.get("commands_sent", 0),
            "cmd_ok": delta("cmd_ok"),
            "cmd_rejected": delta("cmd_rejected"),
            "cmd_forged_ok": delta("cmd_forged_ok"),
            "kicked": delta("kicked"),
            "lat_p50_us": round(summary["latency_us"]["p50"]),
            "lat_p99_us": round(summary["latency_us"]["p99"]),
            "lat_p999_us": round(summary["latency_us"].get("p999", 0)),
            "lat_max_us": round(summary["latency_us"].get("max", 0)),
            "gw_cpu_pct": summary["cpu_pct"],
            "gw_cpu_us_per_msg": summary["cpu_us_per_msg"],
            "broker_cpu_pct": round(100.0 * (b1 - b0) / (t1 - t0), 1) if pid0 == pid1 else "",
            "gw_rss_peak_kb": peaks["gateway"],
            "broker_rss_peak_kb": peaks["broker"],
            **bytes_split,
            "sensors_up": f1["up"],
            "attacker_connected": bool(a1.get("connected")),
            "attacker": a1["detail"],
            "attack_republished": attack("republished"),
            "attack_relabelled": attack("relabelled"),
            "attack_stolen_sent": attack("stolen_sent"),
            "attack_commands_forged": attack("commands_forged"),
            "slow_held": a1.get("slow_held", 0),
            "probe_ok": attack("probe_ok"),
            "probe_failed": attack("probe_failed"),
            "probe_ms": round(a1.get("probe_ms", 0.0), 1),
            "wire_publishes": relay("publishes"),
            "wire_readable_pct": share(relay("readable"), relay("publishes")),
            "wire_opaque_bytes": relay("opaque_bytes"),
            "tampered": relay("tampered"),
            **self.clock_state(),
        }
        if connect_test:
            result.update(self.connect_cost(connect_test))
        return result

    def clock_state(self) -> dict:
        """How far the sensors' clocks are from the gateway's (report §6.6: Δa and
        Δs are to be calibrated from the measured latency and clock skew).

        Agents estimate their offset to the controller NTP-style; the sensors on
        an agent correct their timestamps by it unless --no-clock-correction.
        `clock_offset_ms_max` is the largest |offset| (the skew a receiver
        would see without correction), `clock_uncertainty_ms_max` the largest
        residual after correction (best RTT / 2). Local sensors share the
        gateway's clock: source "local", skew 0 (nothing to calibrate from)."""
        if not self.sensor_agents:
            return {"clock_source": "local", "clock_offset_ms_max": 0.0,
                    "clock_uncertainty_ms_max": 0.0, "clock_corrected": ""}
        clocks = [a.clock for a in self.sensor_agents if a.clock.get("offset_ns") is not None]
        if not clocks:
            return {"clock_source": "agents", "clock_offset_ms_max": "",
                    "clock_uncertainty_ms_max": "", "clock_corrected": ""}
        return {"clock_source": "agents",
                "clock_offset_ms_max": round(max(abs(c["offset_ns"]) for c in clocks) / 1e6, 3),
                "clock_uncertainty_ms_max": round(
                    max(c.get("uncertainty_ns", 0) for c in clocks) / 1e6, 3),
                "clock_corrected": int(all(c.get("corrected", True) for c in clocks))}

    def connect_cost(self, count: int) -> dict:
        """Gateway reconnections timed by the gateway itself (H4: is TLS's cost
        in establishing the connection?)."""
        try:
            r = self.gateway.connect_test(count)
        except Exception:  # noqa: BLE001 - a timeout must not lose the whole cell
            return {"connect_ms_p50": "", "connect_ms_max": "", "connect_cpu_ms": "",
                    "connect_failed": count}
        samples = sorted(r.get("samples_ms", []))
        ok = len(samples)
        return {"connect_ms_p50": round(samples[ok // 2], 2) if ok else "",
                "connect_ms_max": round(samples[-1], 2) if ok else "",
                "connect_cpu_ms": round(r.get("cpu_ms", 0.0) / max(ok, 1), 3),
                "connect_failed": r.get("failed", 0)}

    def recovery_time(self, baseline_msg_s: float, timeout: float = 30.0,
                      fraction: float = 0.9) -> float | str:
        """Seconds until the gateway delivers again at `fraction` of the
        pre-attack rate (polled from the per-second stats); '' if it does not
        recover within `timeout`."""
        t0 = self.now()
        last = None
        while self.now() - t0 < timeout:
            time.sleep(0.25)
            point = self.history[-1] if self.history else None
            if point is not None and point is not last and point["t"] > t0:
                last = point
                if point["delivered"] >= fraction * baseline_msg_s:
                    return round(point["t"] - t0, 2)
        return ""
