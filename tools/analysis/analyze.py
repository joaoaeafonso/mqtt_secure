#!/usr/bin/env python3
"""Rebuilds every table and figure of the Part 2 report from a campaign's raw
data (report §7.5–7.6). Pure Python (standard library only), deterministic.

    tools/analysis/analyze.py results/<campaign> [results/<other> ...] [--out build/analysis]

Input (written by `loadgen.py campaign`, never modified here):
    runs.csv, levels.json, params.toml (frozen), manifest.json,
    attacks.csv (optional), saturation.csv (optional), microbench/*.json (optional)

Output, per campaign, in <out>/<campaign name>/:
    summary.csv / summary.tex    median and 95 % bootstrap CI over runs, per
                                 configuration and metric
    marginal.csv / marginal.tex  cost of each layer: m(c_l=1) − m(c_l=0), CI
    interaction.csv              difference of differences for pairs of layers
    protection.csv               π_a(c) and S(c)
    criterion.csv / criterion.tex
                                 cost(c), S(c), feasibility, use-case filter,
                                 Pareto frontier, c* and Δcost/ΔS per use case
    hypotheses.md                the numbers H1–H5 are judged on
    calibration.md / .csv        Δa and Δs proposed from the measured latency and
                                 clock skew (report §6.6)
    microbench.csv / .tex        level 1: ns per message by profile, size, AES on/off
                                 (levels with a pipeline profile: K0, K2–K7, K9, K11;
                                 K1, K8 and K10 differ only in transport and limits)
    fig-*.tex                    pgfplots figures (\\input them in the report)
    README.md                    what was computed, with which parameters, and
                                 whether the parameters were still provisional

The CIs are percentile bootstrap intervals of the median, resampling runs
(not messages), with a fixed seed from params.toml.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Cost metrics: (column, higher is worse?, label).
METRICS = [
    ("gw_cpu_us_per_msg", True, "CPU do gateway (µs/msg)"),
    ("lat_p50_us", True, "latência p50 (µs)"),
    ("lat_p99_us", True, "latência p99 (µs)"),
    ("delivered_msg_s", False, "débito entregue (msg/s)"),
    ("loss_pct", True, "perda (%)"),
    ("broker_cpu_pct", True, "CPU do broker (%)"),
    ("gw_rss_peak_kb", True, "memória do gateway (KiB)"),
    ("broker_rss_peak_kb", True, "memória do broker (KiB)"),
    ("bytes_total", True, "octetos por mensagem"),
    ("bytes_envelope", True, "octetos do envelope"),
    ("bytes_tls_other", True, "octetos TLS e outros"),
    ("connect_ms_p50", True, "estabelecimento de ligação (ms)"),
    ("connect_cpu_ms", True, "CPU por ligação (ms)"),
    ("lat_p999_us", True, "latência p99,9 (µs)"),
    ("lat_max_us", True, "latência máxima (µs)"),
    ("clock_offset_ms_max", True, "desvio de relógio máximo (ms)"),
]
LOWER_IS_BETTER = {m: worse for m, worse, _ in METRICS} | {"throughput": False}

# The cost of one layer: the two levels that differ only in it (report §7.6).
MARGINAL_PAIRS = [
    ("K0", "K1", "transporte (mTLS 1.3, autenticação, ACL)"),
    ("K1", "K2", "envelope de autenticação (GMAC)"),
    ("K2", "K3", "cifra (AES-256-GCM em vez de GMAC)"),
    ("K3", "K4", "validade temporal"),
    ("K3", "K5", "janela anti-repetição"),
    ("K6", "K7", "restrição chave–tópico"),
    ("K7", "K8", "limitação de tráfego e limites do broker"),
    ("K8", "K9", "assinatura Ed25519 em vez de AES-GCM"),
    ("K10", "K7", "TLS com o envelope já ativo"),
    ("K8", "K11", "ChaCha20-Poly1305 em vez de AES-256-GCM"),
]
# Interactions: (a1 − a0) − (b1 − b0), i.e. does layer X cost the same with and
# without layer Y? Only pairs the level design makes measurable.
INTERACTIONS = [
    ("validade × anti-repetição", ("K5", "K6"), ("K3", "K4")),   # validity with vs without window
    ("TLS × envelope", ("K10", "K7"), ("K0", "K1")),              # TLS with vs without envelope
]
# Level-1 profile per level (benchmarks/pipeline_benchmarks.cpp, zone noacl).
MICROBENCH_PROFILE = {
    "K0": "0_baseline", "K2": "2_auth_only", "K3": "3_aead", "K4": "4_aead_freshness",
    "K5": "5_aead_replay", "K6": "6_full", "K7": "10_full_key_binding", "K9": "9_sign",
    "K11": "11_full_key_binding_chacha20",
}
# Level-1 result files (tools/analysis/microbench.py) → variant, in table order.
# armcap0 switches every ARM extension off (NEON too, which ChaCha20 uses);
# armcap1 keeps NEON and drops only the crypto extensions, like a Cortex-A
# without them (written on ARM only).
MICROBENCH_VARIANTS = {"aes-on": "aes-on", "aes-armcap1": "aes-off-neon",
                       "aes-armcap0": "aes-off"}
VARIANT_LABEL = {"aes-on": "sim", "aes-off-neon": "não (NEON)", "aes-off": "não"}
# Use cases (report §7.5): properties a configuration must have to be admissible.
USE_CASES = {
    "telemetria-nao-sensivel": {"integrity", "topic_binding", "anti_replay"},
    "telemetria-sensivel": {"integrity", "topic_binding", "anti_replay", "confidentiality"},
    "ordens": {"integrity", "freshness", "anti_replay", "key_binding", "origin_proof"},
}


# ------------------------------------------------------------------ helpers ---

def num(value) -> float | None:
    try:
        x = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(x) else x


def median(xs: list[float]) -> float:
    return statistics.median(xs)


def bootstrap(groups: list[list[float]], stat, rng: random.Random, resamples: int,
              confidence: float) -> tuple[float, float, float]:
    """Point estimate and percentile CI of stat(*groups), resampling each group."""
    point = stat(*groups)
    if any(len(g) < 2 for g in groups):
        return point, point, point
    draws = sorted(stat(*[rng.choices(g, k=len(g)) for g in groups]) for _ in range(resamples))
    lo = draws[int((1 - confidence) / 2 * (resamples - 1))]
    hi = draws[int((1 + confidence) / 2 * (resamples - 1))]
    return point, lo, hi


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict]) -> None:
    columns = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, restval="")
        writer.writeheader()
        writer.writerows(rows)


def fmt(x, digits: int = 1, tex: bool = True) -> str:
    """A number for a table: LaTeX by default; tex=False for the Markdown outputs."""
    if x is None or x == "":
        return "--"
    if isinstance(x, str):
        return x
    if abs(x) >= 1000:
        return f"{x:,.0f}".replace(",", "\\," if tex else " ")
    return f"{x:.{digits}f}"


def fmt_md(x, digits: int = 1) -> str:
    return fmt(x, digits, tex=False)


def natural(value) -> tuple:
    """Sort key that orders numbers numerically and everything else as text."""
    x = num(value)
    return (0, x, "") if x is not None else (1, 0.0, str(value))


def tex_escape(text: str) -> str:
    return (str(text).replace("\\", "\\textbackslash{}").replace("_", "\\_")
            .replace("%", "\\%").replace("&", "\\&").replace("#", "\\#"))


def tex_table_lines(caption: str, label: str, header: list[str], rows: list[list[str]],
                    spec: str | None = None, size: str = "small") -> list[str]:
    spec = spec or "l" + "r" * (len(header) - 1)
    lines = ["\\begin{table}[ht]", "  \\centering", f"  \\caption{{{caption}}}",
             f"  \\label{{{label}}}", f"  \\{size}", "  \\setlength{\\tabcolsep}{4pt}",
             f"  \\begin{{tabular}}{{@{{}}{spec}@{{}}}}",
             "    \\toprule", "    " + " & ".join(f"\\textbf{{{h}}}" for h in header) + " \\\\",
             "    \\midrule"]
    lines += ["    " + " & ".join(r) + " \\\\" for r in rows]
    lines += ["    \\bottomrule", "  \\end{tabular}", "\\end{table}", ""]
    return lines


def tex_table(path: Path, caption: str, label: str, header: list[str], rows: list[list[str]],
              spec: str | None = None, size: str = "small") -> None:
    path.write_text("\n".join(["% Generated by tools/analysis/analyze.py; do not edit by hand.",
                               *tex_table_lines(caption, label, header, rows, spec, size)]),
                    encoding="utf-8")


# ------------------------------------------------------------------ campaign ---

class Campaign:
    def __init__(self, root: Path, params_override: Path | None) -> None:
        self.root = root
        self.runs = read_csv(root / "runs.csv")
        if not self.runs:
            raise ValueError(f"{root}: no runs.csv (is this a campaign directory?)")
        self.levels = {lv["id"]: lv for lv in json.loads((root / "levels.json").read_text())}
        self.manifest = json.loads((root / "manifest.json").read_text())
        params_path = params_override or root / "params.toml"
        self.params = tomllib.loads(params_path.read_text())
        self.params_path = params_path
        self.attacks = read_csv(root / "attacks.csv")
        self.saturation = read_csv(root / "saturation.csv")
        b = self.params.get("bootstrap", {})
        self.rng = random.Random(b.get("seed", 1))
        self.resamples = int(b.get("resamples", 10000))
        self.confidence = float(b.get("confidence", 0.95))
        # Factors: everything that defines a configuration besides the level.
        self.factors = [k for k in self.runs[0] if "." in k]
        for r in self.runs:
            r["bytes_total"] = r.get("bytes_wire") or (
                sum(num(r.get(k)) or 0 for k in ("bytes_payload", "bytes_envelope", "bytes_mqtt"))
                if r.get("bytes_payload") else "")
        self.provisional = (self.params.get("status") != "fixed"
                            or "r_target_msg_s" not in self.params.get("feasibility", {})
                            or "l_max_us" not in self.params.get("feasibility", {}))

    def context(self, row: dict) -> tuple:
        return tuple(row.get(f, "") for f in self.factors)

    def contexts(self) -> list[tuple]:
        """Every combination of the --vary factors, in a fixed order (not the
        randomised run order): the first one is the context of the headline
        tables and figures."""
        return sorted(dict.fromkeys(self.context(r) for r in self.runs),
                      key=lambda ctx: tuple(natural(v) for v in ctx))

    def values(self, level: str, ctx: tuple, metric: str) -> list[float]:
        return [x for r in self.runs if r["level"] == level and self.context(r) == ctx
                if (x := num(r.get(metric))) is not None]

    def level_ids(self) -> list[str]:
        present = {r["level"] for r in self.runs}
        return [lv for lv in self.levels if lv in present]

    def ci(self, groups, stat):
        return bootstrap(groups, stat, self.rng, self.resamples, self.confidence)

    def ctx_label(self, ctx: tuple) -> str:
        return ", ".join(f"{f}={v}" for f, v in zip(self.factors, ctx)) or "—"


# -------------------------------------------------------------------- steps ---

def summary(c: Campaign, out: Path) -> dict:
    rows, table = [], {}
    for ctx in c.contexts():
        for level in c.level_ids():
            row = {"level": level, **dict(zip(c.factors, ctx))}
            for metric, _, _ in METRICS:
                xs = c.values(level, ctx, metric)
                if not xs:
                    continue
                m, lo, hi = c.ci([xs], median)
                row.update({metric: round(m, 3), f"{metric}_lo": round(lo, 3),
                            f"{metric}_hi": round(hi, 3), f"{metric}_n": len(xs)})
                table[(level, ctx, metric)] = (m, lo, hi)
            rows.append(row)
    write_csv(out / "summary.csv", rows)
    # Two tables of three metrics each: six "median [CI]" columns do not fit a page.
    parts = [("", "processador, latência", [("gw_cpu_us_per_msg", "CPU (µs/msg)"),
                                              ("lat_p50_us", "p50 (µs)"),
                                              ("lat_p99_us", "p99 (µs)")]),
             ("-b", "memória, octetos, ligação", [("gw_rss_peak_kb", "Memória (KiB)"),
                                                  ("bytes_total", "Octetos/msg"),
                                                  ("connect_ms_p50", "Ligação (ms)")])]
    for i, ctx in enumerate(c.contexts()):
        suffix = "" if i == 0 else f"-{i}"
        lines = ["% Generated by tools/analysis/analyze.py; do not edit by hand."]
        for part, what, shown in parts:
            body = []
            for level in c.level_ids():
                cells = [level]
                for m, _ in shown:
                    v = table.get((level, ctx, m))
                    cells.append(f"{fmt(v[0])} [{fmt(v[1])}, {fmt(v[2])}]" if v else "--")
                body.append(cells)
            lines += tex_table_lines(
                f"Custo por configuração ({what}): mediana e IC 95\\,\\% por "
                f"\\emph{{bootstrap}} sobre as execuções ({tex_escape(c.ctx_label(ctx))}).",
                f"tab:resumo{part}{suffix}", ["Config."] + [lbl for _, lbl in shown], body,
                size="footnotesize")
        (out / f"summary{suffix}.tex").write_text("\n".join(lines), encoding="utf-8")
    return table


def marginal(c: Campaign, out: Path) -> list[dict]:
    rows = []
    diff = lambda a, b: median(b) - median(a)  # noqa: E731
    for ctx in c.contexts():
        for a, b, layer in MARGINAL_PAIRS:
            for metric, _, _ in METRICS:
                xa, xb = c.values(a, ctx, metric), c.values(b, ctx, metric)
                if not xa or not xb:
                    continue
                d, lo, hi = c.ci([xa, xb], diff)
                rows.append({"layer": layer, "from": a, "to": b, **dict(zip(c.factors, ctx)),
                             "metric": metric, "delta": round(d, 3), "lo": round(lo, 3),
                             "hi": round(hi, 3),
                             "significant": int(lo > 0 or hi < 0)})
    write_csv(out / "marginal.csv", rows)
    if rows:
        ctx0 = c.contexts()[0]
        pick = [r for r in rows if c.context(r) == ctx0 and r["metric"] in
                ("gw_cpu_us_per_msg", "lat_p99_us")]
        body = []
        for a, b, layer in MARGINAL_PAIRS:
            cells = [f"{a}$\\to${b}", tex_escape(layer)]
            for metric in ("gw_cpu_us_per_msg", "lat_p99_us"):
                r = next((r for r in pick if r["from"] == a and r["to"] == b
                          and r["metric"] == metric), None)
                cells.append(f"{fmt(r['delta'])} [{fmt(r['lo'])}, {fmt(r['hi'])}]" if r else "--")
            body.append(cells)
        tex_table(out / "marginal.tex",
                  "Custo marginal de cada camada (diferença de medianas, IC 95\\,\\%).",
                  "tab:marginal", ["Passo", "Camada", "CPU (µs/msg)", "p99 (µs)"], body,
                  "lp{5.2cm}rr", size="footnotesize")
    return rows


def interaction(c: Campaign, out: Path) -> list[dict]:
    rows = []
    did = lambda a0, a1, b0, b1: (median(a1) - median(a0)) - (median(b1) - median(b0))  # noqa: E731
    for ctx in c.contexts():
        for name, (a0, a1), (b0, b1) in INTERACTIONS:
            for metric, _, _ in METRICS:
                groups = [c.values(x, ctx, metric) for x in (a0, a1, b0, b1)]
                if not all(groups):
                    continue
                d, lo, hi = c.ci(groups, did)
                rows.append({"interaction": name, "with": f"{a1}-{a0}", "without": f"{b1}-{b0}",
                             **dict(zip(c.factors, ctx)), "metric": metric,
                             "did": round(d, 3), "lo": round(lo, 3), "hi": round(hi, 3),
                             "interacts": int(lo > 0 or hi < 0)})
    write_csv(out / "interaction.csv", rows)
    return rows


def protection(c: Campaign, out: Path) -> dict[str, float]:
    """π_a(c) (majority over repetitions) and S(c) = Σ ω_a π_a(c) / Σ ω_a."""
    if not c.attacks:
        return {}
    weights = c.params.get("attack_weights", {})
    default = float(weights.get("default", 1.0))
    votes: dict[tuple, list[int]] = defaultdict(list)
    for r in c.attacks:
        votes[(r["level"], r["attack"])].append(int(r["prevented"]))
    attacks = list(dict.fromkeys(a for _, a in votes))
    rows, scores = [], {}
    for level in [lv for lv in c.levels if any(k[0] == lv for k in votes)]:
        row, num_, den = {"level": level}, 0.0, 0.0
        for a in attacks:
            v = votes.get((level, a))
            if not v:
                continue
            pi = int(sum(v) * 2 > len(v))  # majority; ties count as not prevented
            w = float(weights.get(a, default))
            row[a] = pi
            num_, den = num_ + w * pi, den + w
        scores[level] = row["S"] = round(num_ / den, 4) if den else 0.0
        rows.append(row)
    write_csv(out / "protection.csv", rows)
    return scores


def max_throughput(c: Campaign, l_max: float | None) -> dict[str, float]:
    """Largest delivered rate with loss < 1 % (and p99 ≤ L_max if fixed), per
    level, median over saturation repetitions."""
    best: dict[tuple, float] = {}
    for r in c.saturation:
        loss, p99, rate = num(r.get("loss_pct")), num(r.get("lat_p99_us")), num(
            r.get("delivered_msg_s"))
        if loss is None or rate is None or loss >= 1.0 or (l_max and p99 and p99 > l_max):
            continue
        key = (r["level"], r.get("repetition", "1"))
        best[key] = max(best.get(key, 0.0), rate)
    per_level: dict[str, list[float]] = defaultdict(list)
    for (level, _), rate in best.items():
        per_level[level].append(rate)
    return {lv: median(xs) for lv, xs in per_level.items()}


def properties(level: dict) -> set[str]:
    p = level["protection"]
    props = set()
    if p != "none":
        props |= {"integrity", "topic_binding"}
    if p == "encrypt":
        props.add("confidentiality")
    if p == "sign":
        props.add("origin_proof")
    if level["freshness"] and p != "none":
        props.add("freshness")
    if level["replay"] and p != "none":
        props.add("anti_replay")
    if level["key_binding"] and p != "none":
        props.add("key_binding")
    return props


def criterion(c: Campaign, out: Path, table: dict, scores: dict[str, float]) -> list[dict]:
    """cost(c), feasibility, use-case filter, Pareto frontier and c* (report Eqs. custo, melhor)."""
    feas = c.params.get("feasibility", {})
    r_target, l_max = feas.get("r_target_msg_s"), feas.get("l_max_us")
    weights = dict(c.params.get("cost_weights", {}))
    throughput = max_throughput(c, l_max)
    rows = []
    for ctx in c.contexts():
        def metric(level: str, m: str) -> float | None:
            if m == "throughput":
                return throughput.get(level)
            v = table.get((level, ctx, m))
            return v[0] if v else None

        # Weights of metrics nobody measured are spread over the others.
        usable = {m: w for m, w in weights.items()
                  if metric("K0", m) not in (None, 0) and any(
                      metric(lv, m) is not None for lv in c.level_ids())}
        total_w = sum(usable.values()) or 1.0
        missing = sorted(set(weights) - set(usable))
        for level in c.level_ids():
            cost, incomplete = 0.0, []
            for m, w in usable.items():
                ref, val = metric("K0", m), metric(level, m)
                if val in (None, 0):
                    incomplete.append(m)  # e.g. never sustained the lowest swept rate
                    continue
                ratio = val / ref if LOWER_IS_BETTER.get(m, True) else ref / val
                cost += (w / total_w) * ratio
            feasible = ""
            if r_target is not None and l_max is not None:
                rate = throughput.get(level, metric(level, "delivered_msg_s"))
                p99 = metric(level, "lat_p99_us")
                feasible = int(bool(rate and p99 and rate >= r_target and p99 <= l_max))
            props = properties(c.levels[level])
            rows.append({"level": level, **dict(zip(c.factors, ctx)),
                         "S": scores.get(level, ""),
                         # No usable metric: the reference K0 was not measured.
                         "cost": "" if incomplete or not usable else round(cost, 4),
                         "incomplete": " ".join(incomplete),
                         "feasible": feasible,
                         **{f"uc_{u}": int(req <= props) for u, req in USE_CASES.items()},
                         "missing_cost_metrics": " ".join(missing)})
    # Pareto frontier and c*, per context and use case.
    for ctx in c.contexts():
        group = [r for r in rows if c.context(r) == ctx]
        for use_case in USE_CASES:
            cand = [r for r in group if r[f"uc_{use_case}"] and r["S"] != "" and r["cost"] != ""
                    and r["feasible"] != 0]
            frontier = [r for r in cand if not any(
                (o["S"] >= r["S"] and o["cost"] <= r["cost"])
                and (o["S"] > r["S"] or o["cost"] < r["cost"]) for o in cand)]
            for r in group:
                r[f"pareto_{use_case}"] = int(r in frontier)
                r[f"best_{use_case}"] = 0
                r[f"dcost_dS_{use_case}"] = ""
            if frontier:
                s_max = max(r["S"] for r in frontier)
                best = min((r for r in frontier if r["S"] == s_max), key=lambda r: r["cost"])
                best[f"best_{use_case}"] = 1
                ordered = sorted(frontier, key=lambda r: (r["S"], r["cost"]))
                for prev, cur in zip(ordered, ordered[1:]):
                    ds = cur["S"] - prev["S"]
                    cur[f"dcost_dS_{use_case}"] = round((cur["cost"] - prev["cost"]) / ds, 4) \
                        if ds else ""
    write_csv(out / "criterion.csv", rows)
    if rows and scores:
        ctx0 = c.contexts()[0]
        body = []
        for r in (r for r in rows if c.context(r) == ctx0):
            marks = []
            for u, short in zip(USE_CASES, ("T", "TS", "O")):
                if r[f"best_{u}"]:
                    marks.append(f"\\textbf{{{short}*}}")
                elif r[f"pareto_{u}"]:
                    marks.append(short)
            body.append([r["level"], fmt(r["S"], 2), fmt(r["cost"], 2),
                         {1: "sim", 0: "não", "": "--"}[r["feasible"]], " ".join(marks) or "--"])
        note = " Resultados provisórios: parâmetros ainda não fixados." if c.provisional else ""
        tex_table(out / "criterion.tex",
                  "Proteção $S(c)$, custo $\\operatorname{custo}(c)$, exequibilidade e fronteira "
                  "de Pareto por caso de uso (T telemetria não sensível, TS telemetria sensível, "
                  "O ordens; * configuração recomendada $c^*$)." + note,
                  "tab:criterio", ["Config.", "$S(c)$", "Custo", "Exequível", "Pareto"], body,
                  "lrrcl")
    return rows


def microbench(c: Campaign, out: Path) -> None:
    """Level 1: google-benchmark JSON files written by tools/analysis/microbench.py."""
    files = sorted((c.root / "microbench").glob("*.json")) if (c.root / "microbench").exists() \
        else []
    samples: dict[tuple, list[float]] = defaultdict(list)
    for path in files:
        data = json.loads(path.read_text())
        variant = MICROBENCH_VARIANTS.get(path.stem)
        if variant is None:
            continue
        for b in data.get("benchmarks", []):
            if b.get("run_type") != "iteration":
                continue
            name = b.get("run_name", b["name"])
            zone, _, rest = name.partition("/")
            profile, _, size = rest.partition("/payload:")
            samples[(variant, zone, profile, size)].append(float(b["cpu_time"]))
    if not samples:
        return
    rows = []
    for (variant, zone, profile, size), xs in sorted(samples.items()):
        m, lo, hi = c.ci([xs], median)
        level = next((lv for lv, p in MICROBENCH_PROFILE.items() if p == profile), "")
        rows.append({"variant": variant, "zone": zone, "profile": profile, "level": level,
                     "payload": size, "ns_per_msg": round(m, 1), "lo": round(lo, 1),
                     "hi": round(hi, 1), "n": len(xs)})
    write_csv(out / "microbench.csv", rows)
    sizes = sorted({r["payload"] for r in rows}, key=int)
    body = []
    for level, profile in MICROBENCH_PROFILE.items():
        for variant in dict.fromkeys(MICROBENCH_VARIANTS.values()):
            if not any(r["variant"] == variant for r in rows):
                continue
            cells = [level, VARIANT_LABEL[variant]]
            for size in sizes:
                r = next((r for r in rows if r["profile"] == profile and r["variant"] == variant
                          and r["zone"] == "noacl" and r["payload"] == size), None)
                cells.append(fmt(r["ns_per_msg"] / 1000, 2) if r else "--")
            body.append(cells)
    tex_table(out / "microbench.tex",
              "Nível 1: tempo de processador por mensagem (µs, mediana das repetições), por "
              "configuração, tamanho e aceleração AES (\\texttt{OPENSSL\\_armcap=0} desliga "
              "todas as extensões ARM; \\texttt{OPENSSL\\_armcap=1} mantém o NEON).",
              "tab:microbench", ["Config.", "AES-HW"] + [f"{s} B" for s in sizes], body)


def figures(c: Campaign, out: Path, table: dict, rows: list[dict]) -> None:
    ctx0 = c.contexts()[0]
    levels = c.level_ids()
    for metric, ylabel, name in (("gw_cpu_us_per_msg", "CPU do gateway (µs/msg)", "cpu"),
                                 ("lat_p99_us", "latência p99 (µs)", "p99")):
        coords = []
        for i, lv in enumerate(levels):
            v = table.get((lv, ctx0, metric))
            if v:
                coords.append(f"({i},{v[0]:.3f}) +- (0,0) -= (0,{v[0] - v[1]:.3f}) "
                              f"+= (0,{v[2] - v[0]:.3f})")
        (out / f"fig-{name}.tex").write_text("\n".join([
            "% Generated by tools/analysis/analyze.py; do not edit by hand.",
            "\\begin{tikzpicture}",
            "  \\begin{axis}[width=\\linewidth, height=5.5cm, ybar, bar width=8pt,",
            f"      ylabel={{{ylabel}}}, xtick={{0,...,{len(levels) - 1}}},",
            f"      xticklabels={{{','.join(levels)}}}, ymin=0,",
            "      error bars/y dir=both, error bars/y explicit]",
            "    \\addplot+[error bars/.cd, y dir=both, y explicit] coordinates {",
            *[f"      {p}" for p in coords], "    };", "  \\end{axis}", "\\end{tikzpicture}",
            ""]), encoding="utf-8")
    pts = [r for r in rows if c.context(r) == ctx0 and r["S"] != "" and r["cost"] != ""]
    if pts:
        frontier = sorted((r for r in pts if r.get("pareto_telemetria-sensivel")),
                          key=lambda r: r["cost"])
        (out / "fig-pareto.tex").write_text("\n".join([
            "% Generated by tools/analysis/analyze.py; do not edit by hand.",
            "\\begin{tikzpicture}",
            "  \\begin{axis}[width=\\linewidth, height=6cm, xlabel={custo$(c)$},",
            "      ylabel={$S(c)$}, ymin=0, ymax=1.05, nodes near coords,",
            "      point meta=explicit symbolic]",
            "    \\addplot+[only marks] coordinates {",
            *[f"      ({r['cost']},{r['S']}) [{r['level']}]" for r in pts], "    };",
            "    \\addplot+[no marks, dashed] coordinates {",
            *[f"      ({r['cost']},{r['S']})" for r in frontier], "    };",
            "  \\end{axis}", "\\end{tikzpicture}", ""]), encoding="utf-8")


def hypotheses(c: Campaign, out: Path, table: dict, marg: list[dict]) -> None:
    """The numbers each hypothesis is judged on; the verdict is the authors'."""
    ctx0 = c.contexts()[0]

    def v(level, m):
        x = table.get((level, ctx0, m))
        return f"{fmt_md(x[0])} [{fmt_md(x[1])}, {fmt_md(x[2])}]" if x else "não medido"

    def d(a, b, m):
        r = next((r for r in marg if r["from"] == a and r["to"] == b and r["metric"] == m
                  and c.context(r) == ctx0), None)
        return (f"{fmt_md(r['delta'])} [{fmt_md(r['lo'])}, {fmt_md(r['hi'])}]"
                f"{' (≠ 0)' if r['significant'] else ' (IC inclui 0)'}") if r else "não medido"

    def flood(level: str, column: str) -> str:
        """Median over the attack repetitions of one column of the flood rows."""
        xs = [x for r in c.attacks if r["attack"] == "flood" and r["level"] == level
              if (x := num(r.get(column))) is not None]
        return fmt_md(median(xs)) if xs else "não medido"
    lines = [
        f"# Hipóteses — evidência ({c.root.name})", "",
        f"Contexto: {c.ctx_label(ctx0)}. Valores: mediana [IC 95 %].", "",
        "## H1 — custo do envelope AES-GCM pequeno face à latência da rede",
        f"- CPU do gateway, K1→K3: {d('K1', 'K3', 'gw_cpu_us_per_msg')} µs/msg",
        f"- latência p50, K1→K3: {d('K1', 'K3', 'lat_p50_us')} µs; latência p50 em K1: "
        f"{v('K1', 'lat_p50_us')} µs", "",
        "## H2 — validade, anti-repetição e chave–tópico quase sem custo",
        f"- validade (K3→K4): CPU {d('K3', 'K4', 'gw_cpu_us_per_msg')}; "
        f"p99 {d('K3', 'K4', 'lat_p99_us')}",
        f"- anti-repetição (K3→K5): CPU {d('K3', 'K5', 'gw_cpu_us_per_msg')}; "
        f"p99 {d('K3', 'K5', 'lat_p99_us')}",
        f"- chave–tópico (K6→K7): CPU {d('K6', 'K7', 'gw_cpu_us_per_msg')}; "
        f"p99 {d('K6', 'K7', 'lat_p99_us')}", "",
        "## H3 — Ed25519 claramente mais caro do que AES-GCM",
        f"- K8→K9: CPU {d('K8', 'K9', 'gw_cpu_us_per_msg')} µs/msg; "
        f"p99 {d('K8', 'K9', 'lat_p99_us')} µs", "",
        "## H4 — custo do TLS concentrado no estabelecimento da ligação",
        f"- estabelecimento: K0 {v('K0', 'connect_ms_p50')} ms, K1 {v('K1', 'connect_ms_p50')} ms;"
        f" CPU por ligação K0 {v('K0', 'connect_cpu_ms')}, K1 {v('K1', 'connect_cpu_ms')} ms",
        f"- por mensagem: K0→K1 CPU {d('K0', 'K1', 'gw_cpu_us_per_msg')} µs/msg; "
        f"TLS com envelope (K10→K7) {d('K10', 'K7', 'gw_cpu_us_per_msg')} µs/msg", "",
        "## H5 — sob inundação, a limitação antes da criptografia reduz o CPU do gateway",
        f"- CPU do gateway sob inundação (attacks.csv, ataque flood, mediana das repetições): "
        f"K7 {flood('K7', 'm_gw_cpu_pct')} %, K8 {flood('K8', 'm_gw_cpu_pct')} %",
        f"- por mensagem recebida: K7 {flood('K7', 'm_gw_cpu_us_per_msg')} µs, "
        f"K8 {flood('K8', 'm_gw_cpu_us_per_msg')} µs; rejeitadas pelo limite: "
        f"K7 {flood('K7', 'm_rate_limited')}, K8 {flood('K8', 'm_rate_limited')}", "",
        "## AES por hardware vs ChaCha20 (QP4)",
        f"- K8→K11: CPU {d('K8', 'K11', 'gw_cpu_us_per_msg')} µs/msg "
        "(ver também microbench.csv com e sem aceleração AES)", ""]
    (out / "hypotheses.md").write_text("\n".join(lines), encoding="utf-8")


def ceil_to(x: float, step: float) -> float:
    return math.ceil(x / step) * step if step > 0 else x


def calibration(c: Campaign, out: Path) -> dict:
    """Proposes Δa and Δs (report §6.6) from the worst legitimate case observed.

    Δs (future timestamps tolerated) must cover the clock skew between a sender
    and the receiver: without correction the agents' |offset|, with it the
    residual (best RTT / 2). Δa (oldest accepted) must cover the slowest
    legitimate delivery plus that skew. Both are multiplied by a safety factor
    and rounded up. The worst case is taken over every run and level, since one
    receiver configuration must accept all legitimate traffic."""
    cal = c.params.get("calibration", {})
    k, step = float(cal.get("safety_factor", 2.0)), float(cal.get("round_ms", 100))
    rows = list(c.runs) + list(c.saturation)

    def worst(col: str) -> float | None:
        xs = [x for r in rows if (x := num(r.get(col))) is not None]
        return max(xs) if xs else None

    lat_max, lat_p999 = worst("lat_max_us"), worst("lat_p999_us")
    offset, residual = worst("clock_offset_ms_max"), worst("clock_uncertainty_ms_max")
    sources = {r.get("clock_source", "") for r in rows} - {""}
    measured_skew = "agents" in sources and offset is not None
    result = {"lat_max_ms": round(lat_max / 1000, 3) if lat_max is not None else "",
              "lat_p999_ms": round(lat_p999 / 1000, 3) if lat_p999 is not None else "",
              "clock_offset_ms": offset if measured_skew else "",
              "clock_residual_ms": residual if measured_skew else "",
              "safety_factor": k, "round_ms": step}
    for name, skew in (("uncorrected", (offset or 0) + (residual or 0)),
                       ("corrected", residual or 0)):
        if lat_max is None or not measured_skew:
            result[f"delta_s_ms_{name}"] = result[f"delta_a_ms_{name}"] = ""
            continue
        result[f"delta_s_ms_{name}"] = ceil_to(max(k * skew, step), step)
        result[f"delta_a_ms_{name}"] = ceil_to(k * (lat_max / 1000 + skew), step)
    write_csv(out / "calibration.csv", [result])

    lines = [f"# Calibração de Δa e Δs ({c.root.name})", "",
             "Relatório §6.6: os valores iniciais (Δa = 60 s, Δs = 5 s) são calibrados a partir "
             "da latência medida e do desvio de relógio observado. Pior caso legítimo em todas "
             "as execuções (custo e saturação), multiplicado por "
             f"{k:g} e arredondado para cima a {step:g} ms.", "",
             f"- latência máxima: {fmt_md(result['lat_max_ms'], 3)} ms "
             f"(p99,9 máximo: {fmt_md(result['lat_p999_ms'], 3)} ms)"]
    if measured_skew:
        lines += [f"- desvio de relógio dos agentes |offset| máximo: {fmt_md(offset, 3)} ms; "
                  f"incerteza residual após correção: {fmt_md(residual, 3)} ms", "",
                  "| | Δs (ms) | Δa (ms) |", "|---|---|---|",
                  f"| relógios sem correção (Δs cobre o offset) | "
                  f"{fmt_md(result['delta_s_ms_uncorrected'], 0)} | "
                  f"{fmt_md(result['delta_a_ms_uncorrected'], 0)} |",
                  f"| relógios sincronizados (resta a incerteza) | "
                  f"{fmt_md(result['delta_s_ms_corrected'], 0)} | "
                  f"{fmt_md(result['delta_a_ms_corrected'], 0)} |", "",
                  "Usar a linha que corresponde ao cenário de implantação (dispositivos com "
                  "NTP/PTP ou não). Valores por omissão por fluxo: ver `FreshnessRule`."]
    else:
        lines += ["", "**Desvio de relógio não medido**: os sensores correram na mesma máquina "
                      "que o gateway (relógio partilhado). Para calibrar Δs, a campanha tem de "
                      "usar agentes (`cluster.sensor_agents`)."]
    (out / "calibration.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def readme(c: Campaign, out: Path) -> None:
    m = c.manifest
    lines = [
        f"# Análise de {c.root.name}", "",
        "Gerado por `tools/analysis/analyze.py` a partir dos dados brutos; não editar.", "",
        f"- código: {m.get('git', {}).get('describe', '?')}; plataforma: "
        f"{m.get('platform', {}).get('cpu', '?')}; {m.get('software', {}).get('openssl', '')}",
        f"- semente da ordem: {m.get('seed')}; execuções: {len(c.runs)}; "
        f"fatores: {', '.join(c.factors) or 'nenhum'}",
        f"- parâmetros: `{c.params_path}` (estado: {c.params.get('status', '?')}; "
        f"SHA-256 congelado: {m.get('params_sha256', '?')[:16]}…)",
        f"- bootstrap: {c.resamples} reamostragens, IC {c.confidence:.0%}, semente "
        f"{c.params.get('bootstrap', {}).get('seed')}",
    ]
    if c.provisional:
        lines += ["", "**PROVISÓRIO**: os pesos ainda não foram validados ou R_alvo/L_max não "
                      "foram fixados (params.toml). S(c), custo(c), a exequibilidade e c* "
                      "não podem ser usados como resultado final."]
    (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def analyze(root: Path, out_root: Path, params: Path | None) -> Path:
    c = Campaign(root, params)
    out = out_root / root.name
    out.mkdir(parents=True, exist_ok=True)
    table = summary(c, out)
    marg = marginal(c, out)
    interaction(c, out)
    scores = protection(c, out)
    rows = criterion(c, out, table, scores)
    microbench(c, out)
    figures(c, out, table, rows)
    hypotheses(c, out, table, marg)
    calibration(c, out)
    readme(c, out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("campaigns", nargs="+", type=Path, help="results/<campaign> directories")
    parser.add_argument("--out", type=Path, default=REPO / "build" / "analysis")
    parser.add_argument("--params", type=Path,
                        help="use these parameters instead of the campaign's frozen copy "
                             "(the output then says so)")
    args = parser.parse_args()
    for root in args.campaigns:
        try:
            out = analyze(root, args.out, args.params)
        except (ValueError, OSError, KeyError) as e:
            sys.exit(f"analyze: {root}: {e}")
        print(f"{root} → {out}")


if __name__ == "__main__":
    main()
