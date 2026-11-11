"""The attack set 𝒜 of the report (Section 7, attack table), run against the
security levels to fill π_a(c): 1 if level c prevents attack a, 0 otherwise.
S(c) (report Eq. "protecao") is computed from it by tools/analysis.

Unlike `scenarios.py`, which isolates one defence per experiment on a
deliberately open baseline, here every attack meets the whole level as
configured (transport, ACL, envelope, checks, limits). An attack that fails at
the broker (e.g. an outsider without credentials under mTLS) counts as
prevented by that level, which is what S(c) should measure.

Insider attacks use a compromised sensor-1 (`stolen_key`): its payload keys,
its broker password and certificate; the real sensor-1 is offline while the
attacker holds it (`attacker.stolen_exclusive`). Network attacks use the relay on the
gateway's link (`wiretap`, startup), which can only read and rewrite
plaintext MQTT: under TLS it is an on-path attacker who sees ciphertext.

Each attack: the settings that mount it (on top of the level), and the
predicate that says it SUCCEEDED in the measured window.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from lab import DEFAULTS


@dataclass(frozen=True)
class Attack:
    name: str
    description: str
    patch: dict
    succeeded: Callable[[dict], bool]
    wiretap: bool = False


def _a(**attacker) -> dict:
    return {"attacker": attacker}


ATTACKS: list[Attack] = [
    Attack("eavesdrop-network", "read readings on the gateway's link",
           {}, lambda r: r["wire_readable_pct"] > 1, wiretap=True),
    Attack("eavesdrop-broker", "read readings as a subscriber to #",
           {}, lambda r: r["leak_readable_pct"] > 1),
    Attack("inject", "publish forged plaintext readings",
           _a(inject_rate=20.0), lambda r: r["forged_ok"] > 0),
    Attack("tamper-on-path", "alter messages on the gateway's link",
           _a(tamper="alter"), lambda r: r["tampered"] > 0 and r["rejected"] < 0.5 * r["tampered"],
           wiretap=True),
    Attack("republish-topic", "copy captured messages to another topic",
           _a(republish_rate=20.0),
           # Relative, not "> 0": success means most of the attacker's copies
           # got in. (The gateway used to count 1–2 republished_ok per window
           # at high rates with no attacker: two sensors drawing the same
           # nanosecond. It now keys the detection by device, see
           # Stats::delivered in apps/load_gateway/main.cpp.)
           lambda r: r["attack_republished"] > 0
           and r["republished_ok"] >= 0.5 * r["attack_republished"]),
    Attack("stolen-key-other-topic", "publish with a device's key on another device's topic",
           _a(stolen_key=1, stolen_rate=20.0, stolen_target="other"),
           lambda r: r["forged_ok"] > 0),
    Attack("replay", "replay recent captured messages",
           _a(replay_rate=20.0), lambda r: r["replays_ok"] > 0),
    Attack("old-unseen-message", "deliver 2-minute-old messages never seen",
           _a(stolen_key=1, stolen_rate=20.0, stolen_age_s=120.0),
           lambda r: r["forged_ok"] > 0),
    Attack("downgrade", "send valid messages in a weaker mode (auth_only)",
           _a(stolen_key=1, stolen_rate=20.0, stolen_mode="auth_only"),
           lambda r: r["forged_ok"] > 0),
    Attack("receiver-forgery", "a compromised actuator forges the gateway's commands",
           {"downlink": {"rate": 20}, **_a(stolen_key=1, forge_commands_rate=20.0)},
           lambda r: r["cmd_forged_ok"] > 0),
    Attack("impersonate", "connect as 'gateway' without its credentials",
           _a(impersonate=True), lambda r: r["attacker_connected"] and r["leak_pct"] > 1),
    Attack("flood", "a compromised device floods its own topic (300 msg/s)",
           _a(stolen_key=1, stolen_rate=300.0),
           # Not `attacker_connected`: that is the state at the window's last
           # instant only; messages sent in the window are the evidence.
           lambda r: r["attack_stolen_sent"] > 0 and r["rate_limited"] == 0),
    Attack("slow-connections", "hold 200 half-open connections (SlowITe)",
           _a(slow_connections=200), lambda r: r["slow_held"] >= 180),
]
ATTACK_BY_NAME = {a.name: a for a in ATTACKS}

# Everything an attack may have changed, back to rest (wiretap stays: startup only).
QUIET: dict = {"attacker": {k: v for k, v in DEFAULTS["attacker"].items() if k != "wiretap"},
               "downlink": {"rate": 0}}


def needs_wiretap(names: list[str] | None = None) -> bool:
    return any(a.wiretap for a in ATTACKS if not names or a.name in names)


def run_matrix(lab, levels, settle: float, duration: float, names: list[str] | None = None,
               log=print, on_row=None) -> list[dict]:
    """π_a(c) for every level × attack: one measured window each."""
    selected = [a for a in ATTACKS if not names or a.name in names]
    rows, n, total = [], 0, len(levels) * len(selected)
    for level in levels:
        for attack in selected:
            n += 1
            if attack.wiretap and not lab.config["attacker"]["wiretap"]:
                log(f"[{n}/{total}] {level.id} × {attack.name}: skipped (no wiretap)")
                continue
            lab.apply(QUIET)
            lab.apply(level.patch(lab.config))
            lab.apply(attack.patch)
            lab.mark(f"attack {attack.name} vs {level.id}")
            result = lab.measure(settle, duration)
            ok = bool(attack.succeeded(result))
            if attack.patch.get("attacker", {}).get("stolen_key"):
                from scenarios import clean_up_compromise
                clean_up_compromise(lab)
            row = {"level": level.id, "attack": attack.name, "succeeded": int(ok),
                   "prevented": int(not ok),
                   **{f"m_{k}": v for k, v in result.items()}}
            log(f"[{n}/{total}] {level.id} × {attack.name}: "
                f"{'SUCCEEDED' if ok else 'prevented'}")
            rows.append(row)
            if on_row:
                on_row(row)
    lab.apply(QUIET)
    return rows
