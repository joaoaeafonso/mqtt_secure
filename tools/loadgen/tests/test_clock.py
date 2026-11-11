"""Agent clock offset estimation (ClockEstimator), with synthetic ping/pong pairs."""

import random
import unittest

from agent import ClockEstimator

S = 1_000_000_000  # ns per second


def feed(clock: ClockEstimator, *, offset_ns: int, drift_ppm: float, seconds: float,
         step_s: float = 0.5, rng: random.Random | None = None, start_s: float = 1000.0) -> float:
    """Pings every `step_s` for `seconds`; the controller's clock is ours plus
    offset_ns + drift. Each ping gets 100–400 µs of RTT, queued asymmetrically
    (that is what the lowest-RTT selection has to see through). Returns the
    monotonic time of the last ping."""
    rng = rng or random.Random(1)
    t = start_s
    end = start_s + seconds
    while t <= end:
        true_offset = offset_ns + drift_ppm * 1e3 * (t - start_s)
        t0 = int(t * S)
        out = rng.randint(50_000, 200_000)
        back = rng.randint(50_000, 200_000)
        t1 = round(t0 + out + true_offset)
        t2 = t0 + out + back
        clock.add(t0, t1, t2, now=t)
        t += step_s
    return end


class ClockEstimatorTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(ClockEstimator().estimate(now=0.0), {})

    def test_too_short_falls_back_to_lowest_rtt_sample(self):
        clock = ClockEstimator()
        clock.add(0, 10 * S // 1000 + 50, 100, now=1.0)       # rtt 100 ns, offset 10 ms
        clock.add(0, 99 * S // 1000, 900_000, now=2.0)        # worse rtt
        est = clock.estimate(now=2.0)
        self.assertFalse(est["fitted"])
        self.assertEqual(est["offset_ns"], 10 * S // 1000)
        self.assertEqual(est["uncertainty_ns"], 50)

    def test_follows_drift_to_now(self):
        """13 ppm (what the Pi pilot showed): the old min-RTT estimate can be
        ~0.8 ms stale; the fit must be within a few tens of µs of the truth."""
        clock = ClockEstimator()
        last = feed(clock, offset_ns=33_000_000, drift_ppm=13.0, seconds=120)
        est = clock.estimate(now=last)
        truth = 33_000_000 + 13.0 * 1e3 * 120
        self.assertTrue(est["fitted"])
        self.assertAlmostEqual(est["drift_ppm"], 13.0, delta=1.0)
        self.assertLess(abs(est["offset_ns"] - truth), 50_000)

    def test_negative_drift(self):
        clock = ClockEstimator()
        last = feed(clock, offset_ns=-40_000_000, drift_ppm=-20.0, seconds=90)
        est = clock.estimate(now=last)
        self.assertAlmostEqual(est["drift_ppm"], -20.0, delta=1.0)
        self.assertLess(abs(est["offset_ns"] - (-40_000_000 - 20.0 * 1e3 * 90)), 50_000)

    def test_no_drift_stays_put(self):
        clock = ClockEstimator()
        last = feed(clock, offset_ns=5_000_000, drift_ppm=0.0, seconds=60)
        est = clock.estimate(now=last)
        self.assertLess(abs(est["drift_ppm"]), 1.0)
        self.assertLess(abs(est["offset_ns"] - 5_000_000), 50_000)

    def test_implausible_drift_falls_back(self):
        """An NTP step inside the window looks like a huge slope: not extrapolated."""
        clock = ClockEstimator()
        last = feed(clock, offset_ns=0, drift_ppm=0.0, seconds=30)
        feed(clock, offset_ns=50_000_000, drift_ppm=0.0, seconds=20, start_s=last + 0.5)
        est = clock.estimate(now=last + 20.5)
        self.assertFalse(est["fitted"])
        # …and the fallback uses the samples after the step, not before it.
        self.assertLess(abs(est["offset_ns"] - 50_000_000), 50_000)

    def test_old_samples_leave_the_window(self):
        clock = ClockEstimator(window_s=60.0)
        last = feed(clock, offset_ns=0, drift_ppm=0.0, seconds=200)
        self.assertLessEqual(clock.estimate(now=last)["samples"], 121)


if __name__ == "__main__":
    unittest.main()
