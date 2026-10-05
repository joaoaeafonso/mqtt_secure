#!/usr/bin/env python3
"""Load lab for mqtt-secure: mock sensors, a private Mosquitto, msec_load_gateway
and an attacker, with every security feature switchable at runtime.

  live     run the lab with a web dashboard; flip features and watch the effect
  matrix   apply each combination of settings in turn, measure, write a table
  scenarios  run the named attack-vs-defence experiments, report PASS/FAIL
  agent    run sensors or an attacker on another machine for a live/matrix controller

Configuration: lab.example.toml documents every setting. Pass a file with
--config and/or override single settings with --set section.key=value.

Examples
  loadgen.py live --set load.sensors=100 --set transport.mode=tls
  loadgen.py live --preset hardened
  loadgen.py matrix --vary transport.mode=plain,tls,mtls --vary payload.protection=none,encrypt

Multiple machines: on the controller (broker + gateway) set
  --set broker.host=0.0.0.0 --set cluster.sensor_agents=2 --set cluster.attacker_agents=1
and run the printed `loadgen.py agent ...` command on each other machine.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import os
import signal
import sys
import threading
import time
import tomllib
from pathlib import Path

from cluster import DEFAULT_CONTROL_PORT, ControllerIdentity, ControlServer
from lab import DEFAULTS, PRESETS, SPEC, STARTUP_ONLY, Lab, merged, uses_agents

REPO = Path(__file__).resolve().parents[2]
DEFAULT_GATEWAY = REPO / "build" / "bench" / "apps" / "load_gateway" / "msec_load_gateway"
DEFAULT_STATE = REPO / "build" / "loadtest" / "controller"


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def parse_value(text: str):
    lowered = text.lower()
    if lowered in ("true", "on", "yes"):
        return True
    if lowered in ("false", "off", "no"):
        return False
    for kind in (int, float):
        try:
            return kind(text)
        except ValueError:
            pass
    return text


def parse_assignment(text: str) -> tuple[str, str, str]:
    key, sep, value = text.partition("=")
    section, dot, name = key.partition(".")
    if not sep or not dot or section not in SPEC or name not in SPEC[section]:
        raise argparse.ArgumentTypeError(
            f"expected section.key=value with a known key, got {text!r}")
    return section, name, value


def load_config(args) -> dict:
    """The full, validated configuration: defaults < --config file < --preset < --set."""
    config: dict = {}
    if args.config:
        with open(args.config, "rb") as f:
            config = tomllib.load(f)
    overrides: dict = {}
    for section, name, value in args.set or []:
        overrides.setdefault(section, {})[name] = parse_value(value)
    for section, values in overrides.items():
        config.setdefault(section, {}).update(values)
    full = merged(DEFAULTS, config)
    if getattr(args, "preset", None):
        # Derived from the load (sensors, rate, payload), so computed after it is known;
        # explicit --set values still win.
        full = merged(merged(full, PRESETS[args.preset](full)), overrides)
    return full


def control_server(args, config: dict) -> ControlServer | None:
    """The agent control plane, when the config places anything on other machines."""
    if not uses_agents(config):
        return None
    identity = ControllerIdentity(args.state_dir, new_token=args.new_token)
    server = ControlServer(identity, config["cluster"]["listen"], config["cluster"]["port"], log)
    server.start()
    return server


# --------------------------------------------------------------------- live ---

def cmd_live(args) -> None:
    from dashboard import serve

    config = load_config(args)
    cluster = control_server(args, config)
    lab = Lab(config, args.gateway, args.workdir, args.verbose, log, cluster)
    server = serve(lab, args.http_host, args.http_port)  # bind early: fail before starting
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    url = f"http://{args.http_host if args.http_host != '0.0.0.0' else '127.0.0.1'}:{args.http_port}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"dashboard: {url}")
    try:
        lab.start()
        log(f"\n  dashboard: {url}\n  API:       curl -s {url}api/config "
            "-d '{\"transport\": {\"mode\": \"tls\"}}'\n  Ctrl-C to stop\n")
        if args.open:
            import webbrowser
            webbrowser.open(url)
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        log("stopping...")
        server.shutdown()
        lab.stop()
        if cluster:
            cluster.stop()


# ------------------------------------------------------------------- matrix ---

def scenarios(vary: list[tuple[str, str, str]]) -> list[dict]:
    """Cartesian product of the --vary lists, as partial configs."""
    axes = [[(s, k, parse_value(v)) for v in values.split(",")] for s, k, values in vary]
    out = []
    for combo in itertools.product(*axes):
        patch: dict = {}
        for s, k, v in combo:
            patch.setdefault(s, {})[k] = v
        out.append(patch)
    return out


def label(patch: dict) -> dict:
    return {f"{s}.{k}": v for s, values in patch.items() for k, v in values.items()}


def cmd_matrix(args) -> None:
    base = load_config(args)
    vary = args.vary or [("transport", "mode", "plain,tls,mtls"),
                         ("payload", "protection", "none,encrypt")]
    # Settings that need a fresh lab (e.g. load.sensors) form the outer loop.
    startup = [v for v in vary if (v[0], v[1]) in STARTUP_ONLY]
    live = [v for v in vary if (v[0], v[1]) not in STARTUP_ONLY]
    outer, inner = scenarios(startup), scenarios(live)
    for patch in outer + inner:
        merged(base, patch)  # validate everything before starting
    total = len(outer) * len(inner)
    out = Path(args.out or REPO / "build" / "loadtest" /
               f"matrix-{time.strftime('%Y%m%d-%H%M%S')}.csv")
    out.parent.mkdir(parents=True, exist_ok=True)

    # One control plane for the whole matrix: agents stay connected between labs.
    cluster = control_server(args, base)
    rows, n = [], 0
    for startup_patch in outer:
        config = merged(base, startup_patch)
        lab = Lab(config, args.gateway, None, args.verbose,
                  log if cluster else (lambda m: None), cluster)
        try:
            lab.start()
            for patch in inner:
                n += 1
                lab.apply(patch)
                settings = {**label(startup_patch), **label(patch)}
                log(f"[{n}/{total}] " + "  ".join(f"{k}={v}" for k, v in settings.items()))
                result = lab.measure(args.settle, args.duration)
                log("      " + "  ".join(f"{k}={v}" for k, v in result.items()))
                rows.append({**settings, **result})
        finally:
            lab.stop()
    if cluster:
        cluster.stop()

    columns = list(rows[0]) if rows else []
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    print("| " + " | ".join(columns) + " |")
    print("|" + "---|" * len(columns))
    for r in rows:
        print("| " + " | ".join(str(r[c]) for c in columns) + " |")
    log(f"\nresults written to {out}")


# ---------------------------------------------------------------- scenarios ---

def cmd_scenarios(args) -> None:
    import scenarios as sc

    if args.list:
        for s in sc.SCENARIOS:
            print(f"{s.name:24} {s.attack} vs {s.defence}\n{'':24} expected: {s.expect}")
        return
    only = set(args.only.split(",")) if args.only else None
    unknown = (only or set()) - {s.name for s in sc.SCENARIOS}
    if unknown:
        raise ValueError(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    config = load_config(args)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out or REPO / "build" / "loadtest" / f"scenarios-{stamp}")
    out.parent.mkdir(parents=True, exist_ok=True)
    cluster = control_server(args, config)
    lab = Lab(config, args.gateway, None, args.verbose,
              log if cluster else (lambda m: None), cluster)
    try:
        lab.start()
        rows = sc.run(lab, args.settle, args.duration, only, log)
    finally:
        lab.stop()
        if cluster:
            cluster.stop()

    with open(out.with_suffix(".csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    table = ["| Scenario | Attack | Defence | Expected | Result | Evidence |",
             "|---|---|---|---|---|---|"]
    table += [f"| {r['scenario']} | {r['attack']} | {r['defence']} | {r['expected']} | "
              f"{r['result']} | {r['evidence']} |" for r in rows]
    out.with_suffix(".md").write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n".join(table))
    failed = [r["scenario"] for r in rows if r["result"] != "PASS"]
    log(f"\n{len(rows) - len(failed)}/{len(rows)} passed; results in {out}.{{md,csv}}")
    if failed:
        sys.exit(f"failed: {', '.join(failed)}")


# -------------------------------------------------------------------- agent ---

def cmd_agent(args) -> None:
    from agent import FatalAgentError, run_agent

    try:
        run_agent(args, log)
    except FatalAgentError as e:
        sys.exit(f"agent: {e}")


# ---------------------------------------------------------------------- CLI ---

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--config", type=Path, help="TOML file (see lab.example.toml)")
        p.add_argument("--set", type=parse_assignment, action="append", metavar="SECTION.KEY=VALUE",
                       help="override one setting; repeatable")
        p.add_argument("--preset", choices=sorted(PRESETS),
                       help="start from a named profile (hardened: every defence on)")
        p.add_argument("--gateway", type=Path, default=DEFAULT_GATEWAY)
        p.add_argument("--verbose", action="store_true", help="gateway logs every rejection")
        p.add_argument("--state-dir", type=Path, default=DEFAULT_STATE,
                       help="controller CA, certificate and agent token (kept between runs)")
        p.add_argument("--new-token", action="store_true", help="rotate the agent join token")

    p = sub.add_parser("live", help="run the lab with a live dashboard")
    common(p)
    p.add_argument("--http-port", type=int, default=8088)
    p.add_argument("--http-host", default="127.0.0.1",
                   help="dashboard bind address; it has no authentication, so keep it local "
                        "or behind an SSH tunnel")
    p.add_argument("--workdir", type=Path, help="keep certificates, keys and logs here")
    p.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("matrix", help="measure every combination of settings")
    common(p)
    p.add_argument("--vary", type=parse_assignment, action="append",
                   metavar="SECTION.KEY=V1,V2,...",
                   help="values to try; repeatable, combined as a cartesian product "
                        "(default: transport.mode × payload.protection)")
    p.add_argument("--settle", type=float, default=3, help="seconds after each change")
    p.add_argument("--duration", type=float, default=10, help="measurement window, seconds")
    p.add_argument("--out", help="CSV path (default build/loadtest/matrix-<time>.csv)")
    p.set_defaults(func=cmd_matrix)

    p = sub.add_parser("scenarios", help="run attack-vs-defence experiments (PASS/FAIL)")
    common(p)
    p.add_argument("--list", action="store_true", help="list the scenarios and exit")
    p.add_argument("--only", help="comma-separated scenario names")
    p.add_argument("--settle", type=float, default=3, help="seconds after each change")
    p.add_argument("--duration", type=float, default=6, help="measurement window, seconds")
    p.add_argument("--out", help="output path without extension "
                                 "(default build/loadtest/scenarios-<time>)")
    p.set_defaults(func=cmd_scenarios)

    p = sub.add_parser("agent", help="run sensors or an attacker for a remote controller")
    p.add_argument("--controller", required=True, help=f"HOST[:PORT] (default port {DEFAULT_CONTROL_PORT})")
    p.add_argument("--token", required=True)
    p.add_argument("--fingerprint", required=True, help="SHA-256 of the controller certificate")
    p.add_argument("--role", choices=("sensors", "attacker"), required=True)
    p.add_argument("--processes", type=int, default=os.cpu_count() or 1,
                   help="sensor worker processes on this machine")
    p.add_argument("--no-clock-correction", dest="clock_correction", action="store_false",
                   help="clocks are already synchronised (e.g. PTP): send raw timestamps")
    p.set_defaults(func=cmd_agent)

    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, RuntimeError) as e:
        sys.exit(f"loadgen: {e}")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()
