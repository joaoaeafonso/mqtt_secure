"""analyze.py on a synthetic campaign: statistics, criterion, Pareto and c*."""

import csv
import json
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import analyze  # noqa: E402

LEVELS = {  # id: protection, freshness, replay, key_binding
    "K0": ("none", False, False, False),
    "K1": ("none", False, False, False),
    "K3": ("encrypt", False, False, False),
    "K6": ("encrypt", True, True, False),
    "K7": ("encrypt", True, True, True),
    "K9": ("sign", True, True, True),
}
CPU = {"K0": 10, "K1": 12, "K3": 14, "K6": 14, "K7": 14, "K9": 60}
P99 = {"K0": 1000, "K1": 1100, "K3": 1150, "K6": 1150, "K7": 1150, "K9": 2000}
PREVENTS = {"K0": 0, "K1": 3, "K3": 5, "K6": 7, "K7": 8, "K9": 9}  # of 10 attacks


def make_campaign(root: Path, status: str = "fixed", feasibility: str = "") -> None:
    rng = random.Random(7)
    (root / "levels.json").write_text(json.dumps([
        {"id": k, "protection": p, "freshness": f, "replay": r, "key_binding": b}
        for k, (p, f, r, b) in LEVELS.items()]))
    (root / "manifest.json").write_text(json.dumps({"seed": 1, "params_sha256": "x" * 64}))
    (root / "params.toml").write_text(
        f'status = "{status}"\n[attack_weights]\ndefault = 1.0\n'
        "[cost_weights]\ngw_cpu_us_per_msg = 0.5\nlat_p99_us = 0.5\n"
        f"[feasibility]\n{feasibility}\n"
        "[bootstrap]\nresamples = 400\nconfidence = 0.95\nseed = 3\n")
    with open(root / "runs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["run", "level", "repetition", "load.payload",
                                          "gw_cpu_us_per_msg", "lat_p99_us", "delivered_msg_s"])
        w.writeheader()
        n = 0
        for level in LEVELS:
            for rep in range(1, 11):
                n += 1
                w.writerow({"run": n, "level": level, "repetition": rep, "load.payload": 64,
                            "gw_cpu_us_per_msg": CPU[level] + rng.gauss(0, 0.3),
                            "lat_p99_us": P99[level] + rng.gauss(0, 20),
                            "delivered_msg_s": 1000})
    with open(root / "attacks.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["level", "attack", "prevented"])
        w.writeheader()
        for level, k in PREVENTS.items():
            for i in range(10):
                w.writerow({"level": level, "attack": f"a{i}", "prevented": int(i < k)})


class Analysis(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "camp"
        self.root.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_analysis(self) -> Path:
        return analyze.analyze(self.root, self.tmp / "out", None)

    def rows(self, out: Path, name: str) -> list[dict]:
        with open(out / name, newline="") as f:
            return list(csv.DictReader(f))

    def test_bootstrap_ci_contains_the_median_and_is_deterministic(self):
        xs = [float(x) for x in range(1, 21)]
        a = analyze.bootstrap([xs], analyze.median, random.Random(1), 500, 0.95)
        b = analyze.bootstrap([xs], analyze.median, random.Random(1), 500, 0.95)
        self.assertEqual(a, b)
        self.assertLessEqual(a[1], a[0])
        self.assertLessEqual(a[0], a[2])

    def test_summary_marginal_and_signature_cost(self):
        make_campaign(self.root)
        out = self.run_analysis()
        marg = {(r["from"], r["to"], r["metric"]): r for r in self.rows(out, "marginal.csv")}
        cpu = marg[("K6", "K7", "gw_cpu_us_per_msg")]
        self.assertAlmostEqual(float(cpu["delta"]), 0.0, delta=0.5)
        self.assertEqual(cpu["significant"], "0")  # key binding: no measurable cost
        self.assertEqual(marg[("K1", "K3", "gw_cpu_us_per_msg")]["significant"]
                         if ("K1", "K3", "gw_cpu_us_per_msg") in marg else "", "")  # no K1→K3 pair
        self.assertEqual(marg[("K0", "K1", "gw_cpu_us_per_msg")]["significant"], "1")
        self.assertTrue((out / "summary.tex").exists())
        self.assertTrue((out / "fig-cpu.tex").exists())

    def test_protection_score(self):
        make_campaign(self.root)
        out = self.run_analysis()
        scores = {r["level"]: float(r["S"]) for r in self.rows(out, "protection.csv")}
        self.assertEqual(scores["K0"], 0.0)
        self.assertEqual(scores["K9"], 0.9)

    def test_criterion_picks_the_cheapest_at_maximum_protection_per_use_case(self):
        make_campaign(self.root)
        out = self.run_analysis()
        rows = {r["level"]: r for r in self.rows(out, "criterion.csv")}
        # Sensitive telemetry needs encryption: K9 (sign) is excluded; K7 is best.
        self.assertEqual(rows["K9"]["uc_telemetria-sensivel"], "0")
        best = [lv for lv, r in rows.items() if r["best_telemetria-sensivel"] == "1"]
        self.assertEqual(best, ["K7"])
        # Commands need proof of origin: only K9 qualifies.
        self.assertEqual([lv for lv, r in rows.items() if r["best_ordens"] == "1"], ["K9"])
        self.assertEqual(float(rows["K0"]["cost"]), 1.0)  # normalised by K0

    def test_feasibility_filter_and_provisional_flag(self):
        make_campaign(self.root, status="proposal")
        out = self.run_analysis()
        self.assertIn("PROVISÓRIO", (out / "README.md").read_text())
        self.assertEqual({r["feasible"] for r in self.rows(out, "criterion.csv")}, {""})

        shutil.rmtree(self.tmp / "out")
        make_campaign(self.root, feasibility="r_target_msg_s = 500\nl_max_us = 1500")
        out = self.run_analysis()
        rows = {r["level"]: r for r in self.rows(out, "criterion.csv")}
        self.assertEqual(rows["K9"]["feasible"], "0")  # p99 2000 µs > L_max
        self.assertEqual(rows["K9"]["best_ordens"], "0")
        self.assertNotIn("PROVISÓRIO", (out / "README.md").read_text())

    def test_r_target_per_use_case(self):
        """Telemetry at a rate only the cheap levels sustain; commands at a lower
        one: K9 (the only level with proof of origin) is infeasible for telemetry
        but still the recommended configuration for commands."""
        sweep = {"K0": 4000, "K1": 4000, "K3": 4000, "K6": 4000, "K7": 4000, "K9": 1000}
        make_campaign(self.root, feasibility=(
            "r_target_msg_s = 3000\nl_max_us = 5000\n"
            "[feasibility.r_target_by_use_case]\nordens = 500"))
        with open(self.root / "saturation.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["level", "repetition", "rate_per_sensor",
                                              "delivered_msg_s", "loss_pct", "lat_p99_us"])
            w.writeheader()
            for level, limit in sweep.items():
                for rep in (1, 2, 3):
                    w.writerow({"level": level, "repetition": rep, "rate_per_sensor": 1,
                                "delivered_msg_s": limit, "loss_pct": 0.0, "lat_p99_us": 2000})
                    w.writerow({"level": level, "repetition": rep, "rate_per_sensor": 2,
                                "delivered_msg_s": limit, "loss_pct": 20.0, "lat_p99_us": 9e6})
        out = self.run_analysis()
        rows = {r["level"]: r for r in self.rows(out, "criterion.csv")}
        self.assertEqual(rows["K9"]["feasible_telemetria-nao-sensivel"], "0")
        self.assertEqual(rows["K9"]["feasible_ordens"], "1")
        self.assertEqual(rows["K9"]["best_ordens"], "1")
        self.assertEqual(rows["K7"]["feasible_telemetria-sensivel"], "1")
        tex = (out / "criterion.tex").read_text()
        self.assertIn("por caso de uso", tex)

    def test_unknown_use_case_in_r_target_is_an_error(self):
        make_campaign(self.root, feasibility=(
            "r_target_msg_s = 3000\nl_max_us = 5000\n"
            "[feasibility.r_target_by_use_case]\ncomandos = 500"))
        with self.assertRaises(SystemExit):
            self.run_analysis()


class Presentation(unittest.TestCase):
    def test_contexts_are_ordered_by_value_not_by_run_order(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            root = tmp / "camp"
            root.mkdir()
            make_campaign(root)
            with open(root / "runs.csv", newline="") as f:
                rows = list(csv.DictReader(f))
            # The randomised order starts with the largest payload.
            rows = ([{**r, "load.payload": 4096} for r in rows]
                    + [{**r, "load.payload": 256} for r in rows] + rows)
            with open(root / "runs.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
            c = analyze.Campaign(root, None)
            self.assertEqual(c.contexts(), [("64",), ("256",), ("4096",)])
        finally:
            shutil.rmtree(tmp)

    def test_thousands_separator_is_latex_only_in_tex(self):
        self.assertEqual(analyze.fmt(12345.6), "12\\,346")
        self.assertNotIn("\\", analyze.fmt_md(12345.6))
        self.assertEqual(analyze.fmt_md(""), "--")

    def test_microbench_variants(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            root = tmp / "camp"
            (root / "microbench").mkdir(parents=True)
            make_campaign(root)
            for stem, ns in (("aes-on", 1000), ("aes-armcap0", 9000), ("aes-armcap1", 8000)):
                (root / "microbench" / f"{stem}.json").write_text(json.dumps({"benchmarks": [
                    {"name": "noacl/3_aead/payload:16", "run_name": "noacl/3_aead/payload:16",
                     "run_type": "iteration", "cpu_time": ns}]}))
            (root / "microbench" / "microbench-manifest.json").write_text("{}")
            out = analyze.analyze(root, tmp / "out", None)
            with open(out / "microbench.csv", newline="") as f:
                got = {r["variant"]: float(r["ns_per_msg"]) for r in csv.DictReader(f)}
            self.assertEqual(got, {"aes-on": 1000, "aes-off": 9000, "aes-off-neon": 8000})
            self.assertIn("não (NEON)", (out / "microbench.tex").read_text())
        finally:
            shutil.rmtree(tmp)


class Calibration(unittest.TestCase):
    """Δa / Δs proposals from latency and clock skew (report §6.6)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "camp"
        self.root.mkdir()
        make_campaign(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def add_columns(self, source, offset, residual, lat_max):
        path = self.root / "runs.csv"
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        for r in rows:
            r.update(clock_source=source, clock_offset_ms_max=offset,
                     clock_uncertainty_ms_max=residual, lat_max_us=lat_max, lat_p999_us=lat_max)
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    def calibration(self) -> dict:
        out = analyze.analyze(self.root, self.tmp / "out", None)
        with open(out / "calibration.csv", newline="") as f:
            return next(csv.DictReader(f)), (out / "calibration.md").read_text()

    def test_proposals_from_agents(self):
        # 12.3 ms offset, 0.4 ms residual, slowest delivery 40 ms; factor 2, round to 100 ms.
        self.add_columns("agents", 12.3, 0.4, 40_000)
        row, _ = self.calibration()
        self.assertEqual(float(row["delta_s_ms_uncorrected"]), 100.0)   # 2 × 12.7 → 100
        self.assertEqual(float(row["delta_a_ms_uncorrected"]), 200.0)   # 2 × 52.7 → 200
        self.assertEqual(float(row["delta_s_ms_corrected"]), 100.0)     # floor of one step
        self.assertEqual(float(row["delta_a_ms_corrected"]), 100.0)     # 2 × 40.4 → 100

    def test_local_sensors_cannot_calibrate_skew(self):
        self.add_columns("local", 0.0, 0.0, 40_000)
        row, text = self.calibration()
        self.assertEqual(row["delta_s_ms_uncorrected"], "")
        self.assertIn("não medido", text)


if __name__ == "__main__":
    unittest.main()
