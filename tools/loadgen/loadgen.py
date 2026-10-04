#!/usr/bin/env python3
"""Load lab for mqtt-secure: mock sensors, a private Mosquitto, msec_load_gateway
and an attacker, with every security feature switchable at runtime.

  live     run the lab with a web dashboard; flip features and watch the effect
  matrix   apply each combination of settings in turn, measure, write a table

Configuration: lab.example.toml documents every setting. Pass a file with
--config and/or override single settings with --set section.key=value.

Examples
  loadgen.py live --set load.sensors=100 --set transport.mode=tls
  loadgen.py matrix --vary transport.mode=plain,tls,mtls --vary payload.protection=none,encrypt
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

from lab import DEFAULTS, SPEC, STARTUP_ONLY, Lab, merged

REPO = Path(__file__).resolve().parents[2]
DEFAULT_GATEWAY = REPO / "build" / "bench" / "apps" / "load_gateway" / "msec_load_gateway"


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
    """The full, validated configuration: defaults < --config file < --set."""
    config: dict = {}
    if args.config:
        with open(args.config, "rb") as f:
            config = tomllib.load(f)
    for section, name, value in args.set or []:
        config.setdefault(section, {})[name] = parse_value(value)
    return merged(DEFAULTS, config)


# --------------------------------------------------------------------- live ---

def cmd_live(args) -> None:
    from dashboard import serve

    lab = Lab(load_config(args), args.gateway, args.workdir, args.verbose, log)
    server = serve(lab, "127.0.0.1", args.http_port)  # bind first: fail before starting anything
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        lab.start()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{args.http_port}/"
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

    rows, n = [], 0
    for startup_patch in outer:
        config = merged(base, startup_patch)
        lab = Lab(config, args.gateway, None, args.verbose, lambda m: None)
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


# ---------------------------------------------------------------------- CLI ---

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--config", type=Path, help="TOML file (see lab.example.toml)")
        p.add_argument("--set", type=parse_assignment, action="append", metavar="SECTION.KEY=VALUE",
                       help="override one setting; repeatable")
        p.add_argument("--gateway", type=Path, default=DEFAULT_GATEWAY)
        p.add_argument("--verbose", action="store_true", help="gateway logs every rejection")

    p = sub.add_parser("live", help="run the lab with a live dashboard")
    common(p)
    p.add_argument("--http-port", type=int, default=8088)
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

    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, RuntimeError) as e:
        sys.exit(f"loadgen: {e}")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()
