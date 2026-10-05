"""Named experiments: one attack against one set of defences, with the outcome
the security design predicts. `loadgen.py scenarios` runs them on one lab,
measures each, and reports PASS/FAIL, so the table doubles as a regression
test for the whole system and as the results table of a report.

Every scenario starts from BASELINE (all live settings at a known value) plus
its own patch, so scenarios do not depend on each other, except the last two:
key rotation and revocation cannot be undone and therefore run last.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from lab import DEFAULTS, hardened

# Live settings every scenario starts from. Sensors publish in the open zone
# with no ACL, so the broker lets everything through and each scenario's
# defence is the only thing standing between the attack and the gateway.
BASELINE: dict = {
    "transport": dict(DEFAULTS["transport"]) | {"acl": False},
    "payload": {k: v for k, v in DEFAULTS["payload"].items() if k != "key_epoch"},
    "storage": dict(DEFAULTS["storage"]),
    "downlink": {"rate": 0},
    "load": {"rate": DEFAULTS["load"]["rate"], "payload": DEFAULTS["load"]["payload"],
             "zone": "open"},
    "attacker": dict(DEFAULTS["attacker"]),
}

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


def _rate_limited(r: Result) -> int:
    return r["rate_limited"]


SCENARIOS: list[Scenario] = [
    Scenario("eavesdrop-open", "subscribe to #", "none",
             "the attacker receives the sensors' traffic",
             lambda r: r["leak_pct"] > 50, {}, ("leak_pct",)),
    Scenario("eavesdrop-acl", "subscribe to #", "topic ACL, restricted zone",
             "nothing reaches the attacker",
             lambda r: r["leak_pct"] == 0 and r["delivered_msg_s"] > 0,
             {"transport": {"acl": True}, "load": {"zone": "restricted"}},
             ("leak_pct", "delivered_msg_s")),
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
             {"payload": {"protection": "none"}, "attacker": {"inject_rate": 20.0}},
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
    Scenario("flood-rate-limit", "flood sensor-1's topic", "gateway rate limit 30 msg/s per topic",
             "the excess is dropped before any crypto",
             lambda r: _rate_limited(r) > 0,
             {"payload": {"rate_limit": 30}, "attacker": {"inject_rate": 150.0}},
             ("rate_limited", "gw_cpu_pct")),
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


def run(lab, settle: float, duration: float, only: set[str] | None = None, log=print) -> list[dict]:
    """Runs the scenarios on a started lab; returns one row per scenario."""
    rows = []
    selected = [s for s in SCENARIOS if not only or s.name in only]
    for n, sc in enumerate(selected, 1):
        patch = sc.patch(lab.config) if callable(sc.patch) else sc.patch
        combined = {section: dict(values) for section, values in BASELINE.items()}
        for section, values in patch.items():
            combined.setdefault(section, {}).update(values)
        log(f"[{n}/{len(selected)}] {sc.name}: {sc.attack} vs {sc.defence}")
        lab.apply(combined)
        result = lab.measure(settle, duration)
        result["sensors_total"] = lab.config["load"]["sensors"]
        ok = bool(sc.check(result))
        evidence = ", ".join(f"{k}={result[k]}" for k in sc.shows)
        log(f"      {'PASS' if ok else 'FAIL'}  {evidence}")
        rows.append({"scenario": sc.name, "attack": sc.attack, "defence": sc.defence,
                     "expected": sc.expect, "result": "PASS" if ok else "FAIL",
                     "evidence": evidence, **{f"m_{k}": v for k, v in result.items()}})
    return rows
