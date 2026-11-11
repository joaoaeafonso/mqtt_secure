"""Measurement campaign (report §7, procedure): every configuration repeated
N times in a random order fixed by a recorded seed, with every run's raw
measurements kept, so tools/analysis can rebuild every table from them.

    results/<name>/
      manifest.json     code, platform, software, seed, arguments, start/end
      config.json       the full base configuration
      levels.json       the K-level definitions used (what each one switches on)
      params.toml       the analysis parameters (weights, R_alvo, L_max), frozen
                        here BEFORE the first measurement; its hash is in the manifest
      plan.csv          every run in execution order (the randomisation)
      runs.csv          one row per run: settings + every metric + thermal state
      attacks.csv       π_a(c): one row per level × attack        (--attacks)
      saturation.csv    load sweep per level until loss ≥ 1 %       (--saturate)

--vary factors apply to the cost runs (runs.csv); the attack matrix and the
saturation sweep run at the base configuration.

Rows are appended as they are measured, so an interrupted campaign keeps
everything measured so far.
"""

from __future__ import annotations

import csv
import dataclasses
import itertools
import json
import random
import shutil
import time
from pathlib import Path

import manifest
from lab import LEVELS, STARTUP_ONLY, Lab, level_patch, merged

DEFAULT_PARAMS = Path(__file__).resolve().parents[1] / "analysis" / "params.toml"


class CsvLog:
    """Appends dict rows to a CSV; the header grows if a later row has new columns."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rows: list[dict] = []

    def add(self, row: dict) -> None:
        self.rows.append(row)
        columns = list(dict.fromkeys(k for r in self.rows for k in r))
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns, restval="")
            writer.writeheader()
            writer.writerows(self.rows)
        tmp.replace(self.path)


def cartesian(vary: list[tuple[str, str, list]]) -> list[dict]:
    axes = [[(s, k, v) for v in values] for s, k, values in vary]
    out = []
    for combo in itertools.product(*axes):
        patch: dict = {}
        for s, k, v in combo:
            patch.setdefault(s, {})[k] = v
        out.append(patch)
    return out


def label(patch: dict) -> dict:
    return {f"{s}.{k}": v for s, values in patch.items() for k, v in values.items()}


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def run_campaign(args, base: dict, make_cluster, repo: Path, log) -> Path:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} is not empty: campaigns never overwrite raw data")
    out.mkdir(parents=True, exist_ok=True)
    levels = [lv for lv in LEVELS if lv.id in args.levels.split(",")] if args.levels else LEVELS
    vary = args.vary or []
    startup = [v for v in vary if (v[0], v[1]) in STARTUP_ONLY]
    live = [v for v in vary if (v[0], v[1]) not in STARTUP_ONLY]
    outer, inner = cartesian(startup) or [{}], cartesian(live) or [{}]
    for patch in outer + inner:
        merged(base, patch)  # validate everything before measuring anything
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(1 << 32)
    rng = random.Random(seed)

    # Fix the analysis parameters before the first measurement.
    params = Path(args.params)
    if not params.exists():
        raise ValueError(f"analysis parameters {params} not found")
    shutil.copyfile(params, out / "params.toml")

    # The plan: per startup combination (one lab each), every (level, live
    # patch) × repetition, shuffled. The startup combinations are shuffled too.
    rng.shuffle(outer)
    plan = []
    for startup_patch in outer:
        cells = [(lv, p, rep) for lv, p in itertools.product(levels, inner)
                 for rep in range(1, args.repetitions + 1)]
        rng.shuffle(cells)
        plan.append((startup_patch, cells))
    with open(out / "plan.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["run", "lab", "level", "repetition", "settings"])
        n = 0
        for i, (sp, cells) in enumerate(plan, 1):
            for lv, p, rep in cells:
                n += 1
                w.writerow([n, i, lv.id, rep, json.dumps({**label(sp), **label(p)})])

    info = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seed": seed,
            "arguments": {k: (str(v) if isinstance(v, Path) else v)
                          for k, v in vars(args).items() if k != "func"},
            "params_sha256": manifest.sha256(out / "params.toml"),
            **manifest.collect(repo, args.gateway)}
    write_json(out / "manifest.json", info)
    write_json(out / "config.json", base)
    write_json(out / "levels.json", [dataclasses.asdict(lv) for lv in levels])

    runs = CsvLog(out / "runs.csv")
    attacks_log = CsvLog(out / "attacks.csv") if args.attacks else None
    saturation = CsvLog(out / "saturation.csv") if args.saturate else None
    cluster = make_cluster(base)
    total = sum(len(c) for _, c in plan)
    n = 0
    try:
        for lab_index, (startup_patch, cells) in enumerate(plan, 1):
            config = merged(base, startup_patch)
            if args.attacks:
                import attacks as attack_module
                if attack_module.needs_wiretap():
                    config = merged(config, {"attacker": {"wiretap": True}})
            lab = Lab(config, args.gateway, None, args.verbose,
                      log if cluster else (lambda m: None), cluster)
            try:
                lab.start()
                for level, patch, rep in cells:
                    n += 1
                    lab.apply(level_patch(level, lab.config, patch))
                    settings = {"level": level.id, "repetition": rep, **label(startup_patch),
                                **label(patch)}
                    lab.mark(f"campaign run {n}/{total}: {settings}")
                    log(f"[{n}/{total}] {'  '.join(f'{k}={v}' for k, v in settings.items())}")
                    result = lab.measure(args.settle, args.duration, args.connect_test)
                    runs.add({"run": n, "lab": lab_index, "time": time.time(), **settings,
                              **result, **manifest.thermal()})
                if cells and (attacks_log is not None or saturation is not None):
                    # The attack matrix and the saturation sweep run at the base
                    # load, not at whatever --vary cell happened to come last.
                    lab.apply(level_patch(LEVELS[0], lab.config, {"load": {
                        k: config["load"][k] for k in ("rate", "payload", "zone")}}))
                if attacks_log is not None:
                    import attacks as attack_module
                    for rep in range(1, args.attack_repetitions + 1):
                        order = list(levels)
                        rng.shuffle(order)
                        attack_module.run_matrix(
                            lab, order, args.settle, args.attack_duration, log=log,
                            on_row=lambda row, rep=rep, sp=startup_patch: attacks_log.add(
                                {"lab": lab_index, "repetition": rep, **label(sp), **row}))
                if saturation is not None:
                    sweep(lab, levels, args, rng, saturation, lab_index, startup_patch, log)
            finally:
                lab.stop()
    finally:
        info["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        info["runs_completed"] = n
        write_json(out / "manifest.json", info)
        if cluster:
            cluster.stop()
    log(f"\ncampaign written to {out} ({n}/{total} runs)")
    return out


def sweep(lab: Lab, levels, args, rng: random.Random, log_rows: CsvLog, lab_index: int,
          startup_patch: dict, log) -> None:
    """Raises load.rate per level until a run loses ≥ 1 % of the messages
    (the report's maximum sustained throughput), `--saturation-repetitions` times."""
    rates = [float(r) for r in args.saturate.split(",")]
    cells = [(lv, rep) for lv in levels for rep in range(1, args.saturation_repetitions + 1)]
    rng.shuffle(cells)
    for level, rep in cells:
        for rate in rates:
            # One step: the level's rate limit follows the load.
            lab.apply(level_patch(level, lab.config, {"load": {"rate": rate}}))
            log(f"saturation {level.id} rep {rep}: {rate} msg/s per sensor")
            result = lab.measure(args.settle, args.saturation_duration)
            log_rows.add({"lab": lab_index, "level": level.id, "repetition": rep,
                          "rate_per_sensor": rate, **label(startup_patch), **result,
                          **manifest.thermal()})
            if result["loss_pct"] >= 1.0:
                # Back to the lowest rate, still at this level, until the
                # overload's backlog is through: it must not leak into the
                # next cell (another key, a lower rate limit).
                lab.apply(level_patch(level, lab.config, {"load": {"rate": rates[0]}}))
                waited = lab.drain()
                log(f"saturation {level.id} rep {rep}: backlog drained in {waited} s")
                break
