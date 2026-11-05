"""Named experiments: one attack against one set of defences, with the outcome
the security design predicts. `loadgen.py scenarios` runs them on one lab,
measures each, and reports PASS/FAIL, so the table doubles as a regression
test for the whole system and as the results table of a report.

Every scenario starts from BASELINE (all live settings at a known value) plus
its own patch, so scenarios do not depend on each other, except the last two:
key rotation and revocation cannot be undone and therefore run last.

Attacks of the report's attack table (Section 7) come in pairs: the scenario
with the defence that should stop the attack, and a `-control` scenario, the
same configuration without that defence, in which the attack must succeed.
A rejection is only attributed to a layer when its control fails as predicted.
Scenarios marked `wiretap` need the gateway's link to run through the
attacker's relay (attacker.wiretap, set at startup; `scenarios` does it).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from lab import DEFAULTS, RELAY_KEYS, hardened
from msec_envelope import AES_GCM

# Live settings every scenario starts from. Sensors publish in the open zone
# with no ACL, so the broker lets everything through and each scenario's
# defence is the only thing standing between the attack and the gateway. The
# payload is encrypted with every check on, so each scenario turns off what it
# examines. Spelled out rather than taken from DEFAULTS (which are level K0),
# so the scenarios' predictions do not depend on the lab's defaults.
BASELINE: dict = {
    "transport": {"mode": "plain", "tls_version": "1.2", "protocol": "3.1.1", "auth": False,
                  "acl": False, "clientid_binding": False, "sys_topics": False,
                  "max_packet": 0, "max_connections": 0},
    "payload": {"protection": "encrypt", "cipher": AES_GCM, "accept": "", "freshness": True,
                "replay": True, "key_binding": True, "rate_limit": 0},
    "storage": dict(DEFAULTS["storage"]),
    "downlink": {"rate": 0},
    "load": {"rate": DEFAULTS["load"]["rate"], "payload": DEFAULTS["load"]["payload"],
             "zone": "open"},
    # wiretap is fixed at startup; the rest (tamper included) is reset every time.
    "attacker": {k: v for k, v in DEFAULTS["attacker"].items() if k != "wiretap"},
}

# The envelope off: every check that needs it must be off as well.
NO_ENVELOPE = {"protection": "none", "freshness": False, "replay": False, "key_binding": False}

Result = dict
Check = Callable[[Result], bool]


@dataclass
class Scenario:
    name: str
    attack: str
    defence: str
    expect: str                       # the prediction, in words
    check: Check
    patch: dict | Callable[[dict], dict] = field(default_factory=dict)
    shows: tuple[str, ...] = ()       # result columns that prove it
    wiretap: bool = False             # needs attacker.wiretap (startup)
    recover: dict | None = None       # attacker patch that ends the attack: time the recovery
    prepare: dict | Callable[[dict], dict] | None = None  # applied and settled before the attack


def _rate_limited(r: Result) -> int:
    return r["rate_limited"]


def _rejected(r: Result, reason: str) -> int:
    """How many messages the gateway rejected for `reason` (an ErrorCode name)."""
    for item in str(r["rejected_by"]).split():
        name, _, count = item.partition("=")
        if name == reason:
            return int(count)
    return 0


def _attack(**settings) -> dict:
    return {"attacker": settings}


SCENARIOS: list[Scenario] = [
    Scenario("eavesdrop-open", "subscribe to #", "none",
             "the attacker receives the sensors' traffic",
             lambda r: r["leak_pct"] > 50, {}, ("leak_pct",)),
    Scenario("eavesdrop-acl", "subscribe to #", "topic ACL, restricted zone",
             "nothing reaches the attacker",
             lambda r: r["leak_pct"] == 0 and r["delivered_msg_s"] > 0,
             {"transport": {"acl": True}, "load": {"zone": "restricted"}},
             ("leak_pct", "delivered_msg_s")),
    # --- eavesdropping: on the network vs at the broker (report: separate the capture point)
    Scenario("eavesdrop-network-control", "capture the gateway's link", "none (plain TCP)",
             "readings are readable on the wire",
             lambda r: r["wire_readable_pct"] > 50,
             {"payload": NO_ENVELOPE}, ("wire_publishes", "wire_readable_pct"), wiretap=True),
    Scenario("eavesdrop-network-tls", "capture the gateway's link", "TLS",
             "the wire shows no MQTT at all, but a subscriber to # still reads everything: "
             "TLS protects each hop, not the broker",
             lambda r: (r["wire_publishes"] == 0 and r["wire_opaque_bytes"] > 0
                        and r["leak_readable_pct"] > 50),
             {"transport": {"mode": "tls", "tls_version": "1.3"}, "payload": NO_ENVELOPE},
             ("wire_publishes", "wire_opaque_bytes", "leak_readable_pct"), wiretap=True),
    Scenario("eavesdrop-broker-encrypt", "subscribe to # and capture the link",
             "envelope, encrypt mode (no TLS)",
             "the broker and the wire carry every message, but no reading is readable; "
             "topic, size and timing still are",
             lambda r: (r["leak_pct"] > 50 and r["leak_readable_pct"] == 0
                        and r["wire_publishes"] > 0 and r["wire_readable_pct"] == 0),
             {}, ("leak_pct", "leak_readable_pct", "wire_readable_pct"), wiretap=True),
    Scenario("impersonate-no-auth", "claim username 'gateway'", "ACL without authentication",
             "a claimed name passes the ACL: the attacker reads the restricted zone",
             lambda r: r["leak_pct"] > 50,
             {"transport": {"acl": True}, "load": {"zone": "restricted"},
              "attacker": {"impersonate": True}}, ("leak_pct", "attacker")),
    Scenario("impersonate-auth", "claim username 'gateway'", "ACL + password authentication",
             "the broker refuses the attacker",
             lambda r: not r["attacker_connected"] and r["leak_pct"] == 0,
             {"transport": {"acl": True, "auth": True}, "load": {"zone": "restricted"},
              "attacker": {"impersonate": True}}, ("attacker_connected", "attacker")),
    Scenario("inject-unprotected", "inject forged readings", "none",
             "the gateway accepts the forgeries",
             lambda r: r["forged_ok"] > 0,
             {"payload": NO_ENVELOPE, "attacker": {"inject_rate": 20.0}},
             ("forged_ok",)),
    Scenario("inject-auth-only", "inject forged readings", "payload authentication (GMAC)",
             "every forgery is rejected",
             lambda r: r["forged_ok"] == 0 and r["rejected"] > 0,
             {"payload": {"protection": "auth_only"}, "attacker": {"inject_rate": 20.0}},
             ("forged_ok", "rejected_by")),
    Scenario("inject-sign", "inject forged readings", "Ed25519 signatures",
             "every forgery is rejected; real traffic still flows",
             lambda r: r["forged_ok"] == 0 and r["rejected"] > 0 and r["delivered_msg_s"] > 0,
             {"payload": {"protection": "sign"}, "attacker": {"inject_rate": 20.0}},
             ("forged_ok", "rejected_by", "gw_cpu_us_per_msg")),
    Scenario("inject-chacha20", "inject forged readings", "envelope with ChaCha20-Poly1305 keys",
             "every forgery is rejected; real traffic, now sealed with ChaCha20 keys, still "
             "flows without rejections",
             lambda r: (r["forged_ok"] == 0 and r["rejected"] > 0 and r["delivered_msg_s"] > 0
                        and r["rejected"] == _rejected(r, "MalformedMessage")
                        and r["loss_pct"] < 5),
             {"payload": {"cipher": "chacha20-poly1305"}, "attacker": {"inject_rate": 20.0}},
             ("forged_ok", "rejected_by", "gw_cpu_us_per_msg")),
    # --- republication on another topic: the topic is in the associated data
    Scenario("republish-topic-control", "copy captured messages to another topic", "none",
             "the copies are accepted as readings of the other topic",
             lambda r: r["attack_republished"] > 0
             and r["republished_ok"] >= 0.5 * r["attack_republished"],
             {"payload": NO_ENVELOPE, **_attack(republish_rate=20.0)},
             ("attack_republished", "republished_ok")),
    Scenario("republish-topic", "copy captured envelopes to another topic",
             "topic in the envelope's associated data",
             "every copy fails authentication (the device may publish there: the key → topic "
             "restriction is not what stops it)",
             lambda r: (r["republished_ok"] < 0.1 * r["attack_republished"]
                        and _rejected(r, "AuthenticationFailed") > 0
                        and _rejected(r, "PermissionDenied") == 0),
             _attack(republish_rate=20.0), ("attack_republished", "republished_ok",
                                            "rejected_by")),
    # --- a stolen key on another device's topic
    Scenario("stolen-key-other-topic-control", "publish with sensor-1's key on sensor-2's topic",
             "envelope without the key → topic restriction",
             "authentic but foreign messages are accepted",
             lambda r: r["forged_ok"] > 0,
             {"payload": {"key_binding": False},
              **_attack(stolen_key=1, stolen_rate=20.0, stolen_target="other")},
             ("attack_stolen_sent", "forged_ok")),
    Scenario("stolen-key-other-topic", "publish with sensor-1's key on sensor-2's topic",
             "key → topic restriction (no ACL: the broker lets it through)",
             "every message is refused after authentication (PermissionDenied)",
             lambda r: r["forged_ok"] == 0 and _rejected(r, "PermissionDenied") > 0,
             _attack(stolen_key=1, stolen_rate=20.0, stolen_target="other"),
             ("attack_stolen_sent", "forged_ok", "rejected_by")),
    Scenario("stolen-key-acl", "publish with sensor-1's key and password on sensor-2's topic",
             "broker ACL (key → topic restriction off)",
             "a legitimate broker refuses the publication before the gateway sees it",
             lambda r: r["forged_ok"] == 0 and r["attack_stolen_sent"] > 0,
             {"transport": {"acl": True, "auth": True}, "load": {"zone": "restricted"},
              "payload": {"key_binding": False},
              **_attack(stolen_key=1, stolen_rate=20.0, stolen_target="other")},
             ("attack_stolen_sent", "forged_ok")),
    # --- an old message never seen before: new sequence numbers, old timestamp
    Scenario("old-unseen-message-control", "deliver 2-minute-old messages never seen before",
             "replay window only (no temporal validity)",
             "the window accepts them: their sequence numbers are new",
             lambda r: r["forged_ok"] > 0,
             {"payload": {"freshness": False},
              **_attack(stolen_key=1, stolen_rate=20.0, stolen_age_s=120.0)},
             ("attack_stolen_sent", "forged_ok")),
    Scenario("old-unseen-message", "deliver 2-minute-old messages never seen before",
             "temporal validity (Δa = 60 s)",
             "every one is refused as expired, before any cryptography",
             lambda r: r["forged_ok"] == 0 and _rejected(r, "MessageExpired") > 0,
             _attack(stolen_key=1, stolen_rate=20.0, stolen_age_s=120.0),
             ("attack_stolen_sent", "forged_ok", "rejected_by")),
    # --- downgrade: relabel without the key; a valid mode outside the policy
    Scenario("downgrade-relabel", "change encrypt → auth_only in captured envelopes",
             "mode in the associated data (receiver accepts both modes)",
             "authentication fails (before the replay window, which would also catch them)",
             lambda r: (r["attack_relabelled"] > 0 and r["replays_ok"] == 0
                        and _rejected(r, "AuthenticationFailed") > 0),
             {"payload": {"accept": "encrypt,auth_only"}, **_attack(relabel_rate=20.0)},
             ("attack_relabelled", "rejected_by")),
    Scenario("downgrade-policy-control", "send valid auth_only messages with a stolen key",
             "receiver accepts encrypt and auth_only",
             "the readable messages are accepted",
             lambda r: r["forged_ok"] > 0,
             {"payload": {"accept": "encrypt,auth_only"},
              **_attack(stolen_key=1, stolen_rate=20.0, stolen_mode="auth_only")},
             ("attack_stolen_sent", "forged_ok")),
    Scenario("downgrade-policy", "send valid auth_only messages with a stolen key",
             "receiver policy: encrypt only",
             "every one is refused (ProtectionNotAccepted)",
             lambda r: r["forged_ok"] == 0 and _rejected(r, "ProtectionNotAccepted") > 0,
             _attack(stolen_key=1, stolen_rate=20.0, stolen_mode="auth_only"),
             ("attack_stolen_sent", "forged_ok", "rejected_by")),
    # --- forgery by a receiver: a compromised actuator forges the gateway's commands
    Scenario("receiver-forgery-control", "actuator sensor-1 forges commands to sensor-2",
             "AES envelope (the group key every actuator holds)",
             "the forged commands are accepted: with a shared key, any receiver can forge",
             lambda r: r["cmd_forged_ok"] > 0,
             {"downlink": {"rate": 20}, **_attack(stolen_key=1, forge_commands_rate=20.0)},
             ("attack_commands_forged", "cmd_forged_ok")),
    Scenario("receiver-forgery", "actuator sensor-1 forges commands to sensor-2",
             "signature mode (actuators hold only the gateway's public key)",
             "no forged command is accepted; the gateway's own commands are",
             lambda r: r["cmd_forged_ok"] == 0 and r["cmd_rejected"] > 0 and r["cmd_ok"] > 0,
             {"payload": {"protection": "sign"}, "downlink": {"rate": 20},
              **_attack(stolen_key=1, forge_commands_rate=20.0)},
             ("attack_commands_forged", "cmd_forged_ok", "cmd_ok")),
    # --- availability
    Scenario("flood-rate-limit", "flood sensor-1's topic", "gateway rate limit 30 msg/s per topic",
             "the excess is dropped before any crypto",
             lambda r: _rate_limited(r) > 0,
             {"payload": {"rate_limit": 30}, "attacker": {"inject_rate": 150.0}},
             ("rate_limited", "gw_cpu_pct", "recovery_s"),
             recover={"inject_rate": 0.0}),
    Scenario("slow-connections-control", "hold 300 half-open connections (SlowITe)",
             "no connection limit",
             "the broker keeps all of them open",
             lambda r: r["slow_held"] >= 270,
             _attack(slow_connections=300, probe_rate=2.0),
             ("slow_held", "probe_ok", "probe_failed", "sensors_up"),
             recover={"slow_connections": 0}),
    Scenario("slow-connections", "hold 300 half-open connections (SlowITe)",
             "broker max_connections = sensors + 16 (in place before the attack)",
             "the broker caps them and connected clients stay up; the spare slots are taken, "
             "so newcomers (the probe) are refused until the attack ends",
             lambda r: (r["slow_held"] <= 16 and r["sensors_up"] == r["sensors_total"]),
             _attack(slow_connections=300, probe_rate=2.0),
             ("slow_held", "probe_ok", "probe_failed", "sensors_up", "recovery_s"),
             recover={"slow_connections": 0},
             prepare=lambda cfg: {"transport": {"max_connections": cfg["load"]["sensors"] + 16}}),
    # --- an active (malicious) broker between the gateway and the real one
    Scenario("active-broker-alter-control", "the broker alters every 2nd message", "none",
             "the altered readings are delivered: nothing notices",
             lambda r: r["tampered"] > 0 and r["rejected"] == 0,
             {"payload": NO_ENVELOPE, "attacker": {"tamper": "alter"}},
             ("tampered", "rejected"), wiretap=True),
    Scenario("active-broker-alter", "the broker alters every 2nd message", "envelope",
             "every altered message fails authentication",
             lambda r: (r["tampered"] > 0
                        and _rejected(r, "AuthenticationFailed") >= 0.9 * r["tampered"]),
             {"attacker": {"tamper": "alter"}}, ("tampered", "rejected_by"), wiretap=True),
    Scenario("active-broker-redirect", "the broker moves every 2nd message to another topic",
             "topic in the associated data",
             "every redirected message fails authentication",
             lambda r: (r["tampered"] > 0
                        and _rejected(r, "AuthenticationFailed") >= 0.9 * r["tampered"]),
             {"attacker": {"tamper": "redirect"}}, ("tampered", "rejected_by"), wiretap=True),
    Scenario("active-broker-delay", "the broker delays every 2nd message by 2 s",
             "temporal validity (Δa = 60 s)",
             "not prevented: a delay shorter than Δa goes unnoticed (it shows only as latency)",
             lambda r: r["tampered"] > 0 and r["rejected"] == 0 and r["lat_p99_us"] >= 1_500_000,
             {"attacker": {"tamper": "delay", "tamper_delay_s": 2.0}},
             ("tampered", "rejected", "lat_p99_us"), wiretap=True),
    Scenario("active-broker-drop", "the broker drops every 2nd message", "envelope",
             "not prevented: suppression is invisible to the receiver (only as loss)",
             lambda r: r["tampered"] > 0 and r["rejected"] == 0 and r["loss_pct"] >= 30,
             {"attacker": {"tamper": "drop"}}, ("tampered", "loss_pct"), wiretap=True),
    Scenario("replay-no-checks", "replay captured messages", "encryption only",
             "authentic old messages are accepted again",
             lambda r: r["replays_ok"] > 0,
             {"payload": {"freshness": False, "replay": False},
              "attacker": {"replay_rate": 20.0}}, ("replays_ok",)),
    Scenario("replay-freshness-only", "replay captured messages", "encryption + 60 s freshness",
             "replays younger than 60 s still get through: freshness alone is not enough",
             lambda r: r["replays_ok"] > 0,
             {"payload": {"freshness": True, "replay": False},
              "attacker": {"replay_rate": 20.0}}, ("replays_ok",)),
    Scenario("replay-window", "replay captured messages", "encryption + replay window",
             "every replay is rejected",
             lambda r: r["replays_ok"] == 0 and "ReplayDetected" in r["rejected_by"],
             {"attacker": {"replay_rate": 20.0}}, ("replays_ok", "rejected_by")),
    Scenario("downlink-commands", "—", "commands protected end to end",
             "every actuator verifies and accepts the gateway's commands",
             lambda r: r["cmd_ok"] > 0 and r["cmd_rejected"] == 0,
             {"downlink": {"rate": 20}}, ("cmd_sent", "cmd_ok", "cmd_rejected")),
    Scenario("modern-transport", "—", "TLS 1.3 + MQTT 5",
             "everything keeps working",
             lambda r: r["delivered_msg_s"] > 0 and r["loss_pct"] < 5,
             {"transport": {"mode": "tls", "tls_version": "1.3", "protocol": "5"}},
             ("delivered_msg_s", "loss_pct")),
    Scenario("hardened", "eavesdrop, impersonate, inject and replay at once",
             "every defence on (the `hardened` preset)",
             "the attacker gets nothing and all legitimate traffic, both ways, still flows",
             lambda r: (not r["attacker_connected"] and r["leak_pct"] == 0
                        and r["forged_ok"] == 0 and r["replays_ok"] == 0
                        and r["delivered_msg_s"] > 0 and r["loss_pct"] < 5 and r["rejected"] == 0
                        and r["sensors_up"] == r["sensors_total"]
                        and r["cmd_ok"] > 0 and r["cmd_rejected"] == 0),
             lambda cfg: {**hardened(cfg), "downlink": {"rate": 20},
                          "attacker": {"impersonate": True, "inject_rate": 20.0,
                                       "replay_rate": 20.0}},
             ("attacker", "leak_pct", "forged_ok", "replays_ok", "delivered_msg_s", "loss_pct",
              "cmd_ok", "gw_cpu_us_per_msg")),
    # Irreversible: keep these last.
    Scenario("key-rotation", "keys captured earlier", "rotate every payload key",
             "traffic continues without rejections across the switch",
             lambda r: r["rejected"] == 0 and r["loss_pct"] < 5,
             lambda cfg: {"payload": {"key_epoch": cfg["payload"]["key_epoch"] + 1}},
             ("rejected", "loss_pct")),
    Scenario("revocation", "a device is compromised", "revoke sensor-1 (keys, password)",
             "sensor-1 is locked out; the others continue",
             lambda r: r["sensors_up"] == r["sensors_total"] - 1 and r["delivered_msg_s"] > 0,
             {"transport": {"auth": True}, "response": {"revoked": "1"}},
             ("sensors_up", "delivered_msg_s")),
]


def needs_wiretap(only: set[str] | None = None) -> bool:
    return any(s.wiretap for s in SCENARIOS if not only or s.name in only)


def deep_merge(base: dict, patch: dict) -> dict:
    """Two-level merge of partial configs: patch wins per key."""
    out = {section: dict(values) for section, values in base.items()}
    for section, values in patch.items():
        out.setdefault(section, {}).update(values)
    return out


def baseline_patch(lab, patch: dict) -> dict:
    """BASELINE + the scenario's patch, keeping the key epoch and the cipher's
    epoch consistent (a cipher change rotates keys: never go backwards)."""
    combined = deep_merge(BASELINE, patch)
    if not lab.config["attacker"]["wiretap"]:
        for key in RELAY_KEYS:
            combined["attacker"].pop(key, None)
    return combined


def clean_up_compromise(lab) -> None:
    """After a compromised-device scenario, rotate every key. Messages the
    stolen key got accepted (in a control) carry sequence numbers far ahead of
    the real device's, so its replay window — and an actuator's window for the
    gateway's key, after forged commands — would reject the genuine traffic
    from then on. That is a real effect of a stolen key; the remedy is the
    real one too: new keys, new windows, and the attacker loses its key."""
    lab.apply({"attacker": {"stolen_key": 0, "stolen_rate": 0.0,
                            "forge_commands_rate": 0.0}})
    lab.apply({"payload": {"key_epoch": lab.config["payload"]["key_epoch"] + 1}})


def run(lab, settle: float, duration: float, only: set[str] | None = None, log=print) -> list[dict]:
    """Runs the scenarios on a started lab; returns one row per scenario."""
    rows = []
    selected = [s for s in SCENARIOS if not only or s.name in only]
    for n, sc in enumerate(selected, 1):
        if sc.wiretap and not lab.config["attacker"]["wiretap"]:
            log(f"[{n}/{len(selected)}] {sc.name}: SKIPPED (needs attacker.wiretap = true)")
            rows.append({"scenario": sc.name, "attack": sc.attack, "defence": sc.defence,
                         "expected": sc.expect, "result": "SKIPPED",
                         "evidence": "attacker.wiretap is off"})
            continue
        patch = sc.patch(lab.config) if callable(sc.patch) else sc.patch
        log(f"[{n}/{len(selected)}] {sc.name}: {sc.attack} vs {sc.defence}")
        lab.mark(f"scenario {sc.name}: {sc.attack} vs {sc.defence}")
        if sc.prepare is not None:
            # The defence first, settled (e.g. a broker restart and every
            # client back), and only then the attack.
            prepare = sc.prepare(lab.config) if callable(sc.prepare) else sc.prepare
            lab.apply(baseline_patch(lab, prepare))
            time.sleep(settle)
            patch = deep_merge(prepare, patch)
        combined = baseline_patch(lab, patch)
        lab.apply(combined)
        result = lab.measure(settle, duration)
        result["sensors_total"] = lab.config["load"]["sensors"]
        result["recovery_s"] = ""
        if sc.recover is not None:
            lab.apply({"attacker": sc.recover})
            result["recovery_s"] = lab.recovery_time(0.9 * result["sent_msg_s"])
        if combined["attacker"].get("stolen_key"):
            clean_up_compromise(lab)
        ok = bool(sc.check(result))
        evidence = ", ".join(f"{k}={result[k]}" for k in sc.shows)
        log(f"      {'PASS' if ok else 'FAIL'}  {evidence}")
        rows.append({"scenario": sc.name, "attack": sc.attack, "defence": sc.defence,
                     "expected": sc.expect, "result": "PASS" if ok else "FAIL",
                     "evidence": evidence, **{f"m_{k}": v for k, v in result.items()}})
    return rows
