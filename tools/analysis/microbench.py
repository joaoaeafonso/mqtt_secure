#!/usr/bin/env python3
"""Level 1 of the evaluation (report §7.3): the pipeline microbenchmarks for
every profile and payload size (16 B … 64 KiB), with and without the CPU's AES
instructions, repeated, in a random interleaved order, raw results kept.

    tools/analysis/microbench.py --out results/<campaign>/microbench [--repetitions 10]

Writes aes-on.json and aes-armcap0.json (google-benchmark JSON, one entry per
repetition) and microbench-manifest.json. `OPENSSL_armcap=0` disables OpenSSL's
ARM crypto extensions (AES, PMULL), the way a device without them would run;
on x86 the equivalent is `OPENSSL_ia32cap=~0x200000200000000` (AES-NI and
PCLMULQDQ off), used automatically there. analyze.py turns them into
microbench.csv/.tex.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO / "build" / "bench" / "benchmarks" / "msec_pipeline_benchmarks"
sys.path.insert(0, str(REPO / "tools" / "loadgen"))
import manifest  # noqa: E402


def no_aes_env() -> dict[str, str]:
    if platform.machine().lower() in ("aarch64", "arm64", "armv7l", "armv8l"):
        return {"OPENSSL_armcap": "0"}
    return {"OPENSSL_ia32cap": "~0x200000200000000"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--min-time", default="0.5s", help="per repetition (google-benchmark)")
    parser.add_argument("--filter", default="noacl/", help="benchmark filter (default: noacl/)")
    args = parser.parse_args()
    if not args.binary.exists():
        sys.exit(f"{args.binary} not found: cmake --preset bench && cmake --build --preset bench")
    args.out.mkdir(parents=True, exist_ok=True)
    runs = {"aes-on": {}, "aes-armcap0": no_aes_env()}
    for name, extra in runs.items():
        path = args.out / f"{name}.json"
        if path.exists():
            sys.exit(f"{path} exists: raw data is never overwritten")
        cmd = [str(args.binary), f"--benchmark_filter={args.filter}",
               f"--benchmark_repetitions={args.repetitions}",
               "--benchmark_enable_random_interleaving=true",
               f"--benchmark_min_time={args.min_time}",
               "--benchmark_format=json", f"--benchmark_out={path}",
               "--benchmark_out_format=json"]
        print(f"{name}: {' '.join(f'{k}={v}' for k, v in extra.items())} {' '.join(cmd)}",
              flush=True)
        subprocess.run(cmd, env={**os.environ, **extra}, check=True, stdout=subprocess.DEVNULL)
    info = {**manifest.collect(REPO, args.binary), "variants": runs,
            "arguments": {k: str(v) for k, v in vars(args).items()}}
    (args.out / "microbench-manifest.json").write_text(json.dumps(info, indent=2) + "\n")
    print(f"written to {args.out}")


if __name__ == "__main__":
    main()
