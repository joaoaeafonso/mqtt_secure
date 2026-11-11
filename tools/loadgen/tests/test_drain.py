"""Saturation sweep: the backlog of an overloaded run is drained before the next cell."""

import random
import types
import unittest
from unittest import mock

import campaign
from lab import DEFAULTS, LEVEL_BY_ID, Lab, merged


class FakeFleet:
    """Sends `rate` messages per poll interval (one fresh_poll pair per interval)."""

    def __init__(self, rate: int) -> None:
        self.rate, self.sent, self.polls = rate, 0, 0

    def fresh_poll(self) -> dict:
        self.polls += 1
        if self.polls % 2 == 0:
            self.sent += self.rate
        return {"sent": self.sent}


class FakeGateway:
    """Takes in what the sensors send plus a backlog, `drain_per_interval` at a time."""

    def __init__(self, fleet: FakeFleet, backlog: int, drain_per_interval: int) -> None:
        self.fleet, self.backlog, self.drain = fleet, backlog, drain_per_interval

    def reset(self) -> None:
        pass

    def summary(self) -> dict:
        extra = min(self.backlog, self.drain)
        self.backlog -= extra
        return {"received": self.fleet.rate + extra // 2, "rejected": extra - extra // 2}


def fake_lab(backlog: int) -> Lab:
    lab = Lab.__new__(Lab)
    lab.fleet = FakeFleet(rate=500)
    lab.gateway = FakeGateway(lab.fleet, backlog, drain_per_interval=4000)
    return lab


@mock.patch("lab.time.sleep", lambda s: None)
class Drain(unittest.TestCase):
    def test_returns_once_the_backlog_is_through(self):
        lab = fake_lab(backlog=10_000)                 # 3 intervals of backlog
        lab.drain(timeout=60, interval=1.0)
        self.assertEqual(lab.gateway.backlog, 0)
        self.assertEqual(lab.fleet.polls, 2 * 5)       # 3 busy + 2 quiet intervals

    def test_no_backlog_is_quick(self):
        lab = fake_lab(backlog=0)
        lab.drain(timeout=60, interval=1.0)
        self.assertEqual(lab.fleet.polls, 2 * 2)

    def test_gives_up_at_the_timeout(self):
        lab = fake_lab(backlog=10**9)
        with mock.patch("lab.time.monotonic", side_effect=[0.0] + [float(i) for i in range(1, 200)]):
            self.assertGreaterEqual(lab.drain(timeout=5, interval=1.0), 5)


class Sweep(unittest.TestCase):
    def test_drains_after_saturation_and_before_the_next_cell(self):
        calls = []
        losses = {("K8", 10.0): 0.0, ("K8", 800.0): 12.0, ("K11", 10.0): 0.0, ("K11", 800.0): 0.0}

        class Lab:
            config = merged(DEFAULTS, {})
            level = None

            def apply(self, patch):
                rate = patch.get("load", {}).get("rate", self.config["load"]["rate"])
                self.config = merged(self.config, patch)
                calls.append(("apply", rate))

            def measure(self, settle, duration):
                calls.append(("measure", self.level.id, self.config["load"]["rate"]))
                return {"loss_pct": losses[(self.level.id, float(self.config["load"]["rate"]))]}

            def drain(self):
                calls.append(("drain",))
                return 1.0

        lab = Lab()
        levels = [LEVEL_BY_ID["K8"], LEVEL_BY_ID["K11"]]
        original = campaign.level_patch

        def level_patch(level, config, extra):
            lab.level = level
            return original(level, config, extra)

        args = types.SimpleNamespace(saturate="10,800", saturation_repetitions=1,
                                     settle=0, saturation_duration=0)
        rows = types.SimpleNamespace(add=lambda row: None)
        with mock.patch.object(campaign, "level_patch", level_patch), \
                mock.patch.object(campaign.manifest, "thermal", lambda: {}):
            campaign.sweep(lab, levels, args, random.Random(1), rows, 1, {}, lambda m: None)

        measured = [c for c in calls if c[0] in ("measure", "drain")]
        k8 = measured.index(("measure", "K8", 800))
        self.assertEqual(measured[k8 + 1], ("drain",), "drain right after the overloaded run")
        self.assertEqual(calls[calls.index(("drain",)) - 1], ("apply", 10.0),
                         "drained at the lowest rate")
        self.assertEqual(measured.count(("drain",)), 1, "no drain when nothing saturated")


if __name__ == "__main__":
    unittest.main()
