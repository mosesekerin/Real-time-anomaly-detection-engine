"""
tests/test_baseline.py

All time is injected — no real sleeping, no time.time() calls in tests.
All sliding window interactions use a real SlidingWindow instance so
the integration between the two components is also verified.
"""

import math
import pytest
from datetime import datetime, timezone
from collections import deque

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.baseline import (
    BaselineEngine, Stats,
    _compute_stats, _cold_default, _hour_of_day,
    MEAN_FLOOR, STDDEV_FLOOR, MIN_SAMPLES_FOR_IP,
    HISTORY_SAMPLES,
)
from detector.sliding_window import SlidingWindow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ts(unix_epoch: float) -> datetime:
    return datetime.fromtimestamp(unix_epoch, tz=timezone.utc)


def build_engine_with_history(ip: str, rates: list, base_now: float = 100_000.0):
    """
    Build a BaselineEngine pre-loaded with `rates` as successive 60s samples
    for `ip`. Simulates recalculate() having been called len(rates) times.

    base_now: starting Unix timestamp. Each recalc advances by 60s.
    """
    window = SlidingWindow(window_seconds=60)
    engine = BaselineEngine(window, now_fn=lambda: base_now)

    for i, rate in enumerate(rates):
        now = base_now + i * 60
        # Inject exactly `rate` requests into the window at this timestamp
        for _ in range(int(rate)):
            window.record(ip, make_ts(now - 1))  # 1s before recalc = inside window
        engine.recalculate(now=now)

    return engine, window, base_now + len(rates) * 60


# ---------------------------------------------------------------------------
# _compute_stats — pure function tests
# ---------------------------------------------------------------------------

class TestComputeStats:

    def test_basic_mean_and_stddev(self):
        samples = [10.0, 20.0, 30.0]
        stats = _compute_stats(samples, hour=9, is_cold=False)
        assert stats.mean == 20.0
        assert stats.hour_segment == 9
        assert stats.is_cold is False

    def test_stddev_correct(self):
        # Variance of [10, 20, 30] = ((100 + 0 + 100) / 3) = 66.67
        # stddev = sqrt(66.67) ≈ 8.16
        samples = [10.0, 20.0, 30.0]
        stats = _compute_stats(samples, hour=0, is_cold=False)
        expected_stddev = math.sqrt(sum((x - 20.0)**2 for x in samples) / 3)
        assert abs(stats.stddev - expected_stddev) < 0.001

    def test_mean_floor_applied(self):
        # Very sparse traffic — mean would be 0.5 without floor
        samples = [0.0, 0.0, 1.0, 0.0, 1.0]
        stats = _compute_stats(samples, hour=3, is_cold=False)
        assert stats.mean >= MEAN_FLOOR

    def test_stddev_floor_applied(self):
        # Perfectly regular traffic — stddev would be 0
        samples = [5.0, 5.0, 5.0, 5.0, 5.0]
        stats = _compute_stats(samples, hour=0, is_cold=False)
        assert stats.stddev >= STDDEV_FLOOR

    def test_single_sample_stddev_floor(self):
        stats = _compute_stats([100.0], hour=0, is_cold=False)
        assert stats.stddev >= STDDEV_FLOOR
        assert stats.sample_count == 1

    def test_empty_samples_returns_cold_default(self):
        stats = _compute_stats([], hour=5, is_cold=False)
        assert stats.is_cold is True
        assert stats.sample_count == 0

    def test_high_traffic_no_floor_interference(self):
        # High traffic — natural mean and stddev should exceed floors
        samples = [100.0, 120.0, 90.0, 110.0, 105.0]
        stats = _compute_stats(samples, hour=10, is_cold=False)
        expected_mean = sum(samples) / len(samples)
        assert abs(stats.mean - expected_mean) < 0.001


# ---------------------------------------------------------------------------
# Stats.z_score
# ---------------------------------------------------------------------------

class TestZScore:

    def test_z_score_at_mean_is_zero(self):
        stats = Stats(mean=10.0, stddev=2.0, sample_count=10,
                      is_cold=False, hour_segment=9)
        assert stats.z_score(10.0) == 0.0

    def test_z_score_one_stddev_above(self):
        stats = Stats(mean=10.0, stddev=2.0, sample_count=10,
                      is_cold=False, hour_segment=9)
        assert stats.z_score(12.0) == 1.0

    def test_z_score_three_stddev_above(self):
        stats = Stats(mean=10.0, stddev=2.0, sample_count=10,
                      is_cold=False, hour_segment=9)
        assert stats.z_score(16.0) == 3.0

    def test_z_score_below_mean_is_negative(self):
        stats = Stats(mean=10.0, stddev=2.0, sample_count=10,
                      is_cold=False, hour_segment=9)
        assert stats.z_score(8.0) == -1.0


# ---------------------------------------------------------------------------
# Cold start behaviour
# ---------------------------------------------------------------------------

class TestColdStart:

    def test_unknown_ip_returns_cold_default(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        stats = engine.get_stats("brand.new.ip", now=100_000.0)
        assert stats.is_cold is True
        assert stats.sample_count == 0

    def test_cold_default_has_wide_band(self):
        """Cold default must not flag normal traffic as anomalous."""
        stats = _cold_default(hour=9)
        # A moderate burst of 20 req/60s should not exceed Z=3 during cold start
        z = stats.z_score(20.0)
        assert z < 3.0, f"Cold start too sensitive: Z={z:.2f} for rate=20"

    def test_ip_below_min_samples_uses_global_fallback(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window, now_fn=lambda: 100_000.0)

        ip = "1.2.3.4"
        # Add fewer samples than MIN_SAMPLES_FOR_IP
        for i in range(MIN_SAMPLES_FOR_IP - 1):
            window.record(ip, make_ts(100_000.0 - 1))
            engine.recalculate(now=100_000.0 + i * 60)

        stats = engine.get_stats(ip, now=100_000.0)
        assert stats.is_cold is True

    def test_ip_at_min_samples_uses_per_ip_stats(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window, now_fn=lambda: 100_000.0)

        ip = "1.2.3.4"
        base = 100_000.0
        for i in range(MIN_SAMPLES_FOR_IP):
            for _ in range(10):
                window.record(ip, make_ts(base + i * 60 - 1))
            engine.recalculate(now=base + i * 60)

        stats = engine.get_stats(ip, now=base + MIN_SAMPLES_FOR_IP * 60)
        assert stats.is_cold is False
        assert stats.sample_count == MIN_SAMPLES_FOR_IP


# ---------------------------------------------------------------------------
# Recalculation and rolling history
# ---------------------------------------------------------------------------

class TestRecalculation:

    def test_recalc_increments_counter(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        engine.recalculate(now=100_000.0)
        engine.recalculate(now=100_060.0)
        assert engine.recalc_count() == 2

    def test_history_capped_at_history_samples(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        ip = "1.2.3.4"

        # Run more recalcs than HISTORY_SAMPLES
        for i in range(HISTORY_SAMPLES + 10):
            for _ in range(5):
                window.record(ip, make_ts(100_000.0 + i * 60 - 1))
            engine.recalculate(now=100_000.0 + i * 60)

        assert engine.sample_count(ip) == HISTORY_SAMPLES

    def test_old_samples_evicted_from_history(self):
        """After HISTORY_SAMPLES+1 recalcs, the very first sample is gone."""
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        ip = "1.2.3.4"

        # First recalc: rate=100 (distinctive)
        for _ in range(100):
            window.record(ip, make_ts(100_000.0 - 1))
        engine.recalculate(now=100_000.0)

        # Fill remaining slots + 1 more with rate=5
        for i in range(1, HISTORY_SAMPLES + 1):
            window = SlidingWindow(window_seconds=60)
            engine._window = window
            for _ in range(5):
                window.record(ip, make_ts(100_000.0 + i * 60 - 1))
            engine.recalculate(now=100_000.0 + i * 60)

        # Mean should now reflect ~5, not pulled toward 100
        stats = engine.get_stats(ip, now=100_000.0 + HISTORY_SAMPLES * 60)
        assert stats.mean < 20.0, "Old high-rate sample was not evicted"


# ---------------------------------------------------------------------------
# Hourly segmentation
# ---------------------------------------------------------------------------

class TestHourlySegmentation:

    def test_hour_of_day_extraction(self):
        # Unix timestamp for 2025-04-28 09:00:00 UTC
        ts = datetime(2025, 4, 28, 9, 0, 0, tzinfo=timezone.utc).timestamp()
        assert _hour_of_day(ts) == 9

    def test_midnight_is_hour_zero(self):
        ts = datetime(2025, 4, 28, 0, 0, 0, tzinfo=timezone.utc).timestamp()
        assert _hour_of_day(ts) == 0

    def test_stats_carry_correct_hour_segment(self):
        samples = [10.0, 12.0, 11.0, 10.0, 11.0]
        stats = _compute_stats(samples, hour=14, is_cold=False)
        assert stats.hour_segment == 14

    def test_global_baseline_segmented_by_hour(self):
        """
        Recalcs at hour=9 and hour=22 build separate global baselines.
        A cold-start IP at hour=9 should get the hour=9 baseline, not hour=22.
        """
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)

        # Hour 9 — low traffic
        ts_9am = datetime(2025, 4, 28, 9, 0, 0, tzinfo=timezone.utc).timestamp()
        for _ in range(5):
            window.record("background", make_ts(ts_9am - 1))
        engine.recalculate(now=ts_9am)

        # Hour 22 — high traffic
        ts_10pm = datetime(2025, 4, 28, 22, 0, 0, tzinfo=timezone.utc).timestamp()
        for _ in range(500):
            window.record("background", make_ts(ts_10pm - 1))
        engine.recalculate(now=ts_10pm)

        # Cold-start IP queried at hour 9 — should get low-traffic baseline
        stats_9am = engine.get_stats("new.ip", now=ts_9am)
        stats_10pm = engine.get_stats("new.ip", now=ts_10pm)

        # Hour 9 mean should be much lower than hour 22 mean
        assert stats_9am.mean < stats_10pm.mean


# ---------------------------------------------------------------------------
# Low-traffic stability (the main false-positive protection)
# ---------------------------------------------------------------------------

class TestLowTrafficStability:

    def test_sparse_ip_does_not_get_extreme_zscore(self):
        """
        IP normally sends 1 req/min. Sudden burst to 3 req/min.
        Without floors, Z = (3 - 0.5) / 0.1 = 25 → false positive.
        With floors, Z should be reasonable.
        """
        samples = [1.0, 0.0, 1.0, 1.0, 0.0]
        stats = _compute_stats(samples, hour=3, is_cold=False)
        z = stats.z_score(3.0)
        assert z < 5.0, f"False positive risk: Z={z:.2f} for sparse IP burst to 3"

    def test_zero_rate_ip_does_not_divide_by_zero(self):
        samples = [0.0, 0.0, 0.0, 0.0, 0.0]
        stats = _compute_stats(samples, hour=0, is_cold=False)
        # Must not raise, must have positive stddev
        assert stats.stddev > 0
        z = stats.z_score(1.0)
        assert math.isfinite(z)

    def test_perfectly_regular_ip_gets_stddev_floor(self):
        samples = [10.0] * 20
        stats = _compute_stats(samples, hour=12, is_cold=False)
        assert stats.stddev == STDDEV_FLOOR

    def test_high_volume_attacker_gets_high_zscore(self):
        """Legitimate high-Z detection still works above floors."""
        # Normal: ~20 req/60s
        samples = [18.0, 20.0, 22.0, 19.0, 21.0] * 6
        stats = _compute_stats(samples, hour=10, is_cold=False)
        # Sudden jump to 200
        z = stats.z_score(200.0)
        assert z > 3.0, "Should detect genuine high-volume attack"


# ---------------------------------------------------------------------------
# Integration: BaselineEngine + SlidingWindow
# ---------------------------------------------------------------------------

class TestEngineIntegration:

    def test_full_warmup_cycle(self):
        """
        Simulate MIN_SAMPLES_FOR_IP recalcs and verify the IP graduates
        from cold to warm baseline.
        """
        engine, window, final_now = build_engine_with_history(
            ip="10.0.0.1",
            rates=[15.0] * MIN_SAMPLES_FOR_IP,
        )
        stats = engine.get_stats("10.0.0.1", now=final_now)
        assert stats.is_cold is False
        assert stats.sample_count == MIN_SAMPLES_FOR_IP

    def test_multiple_ips_tracked_independently(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        base = 100_000.0

        # IP A: consistently 10 req/60s
        # IP B: consistently 100 req/60s
        for i in range(MIN_SAMPLES_FOR_IP):
            now = base + i * 60
            for _ in range(10):
                window.record("ip-a", make_ts(now - 1))
            for _ in range(100):
                window.record("ip-b", make_ts(now - 1))
            engine.recalculate(now=now)

        stats_a = engine.get_stats("ip-a", now=base + MIN_SAMPLES_FOR_IP * 60)
        stats_b = engine.get_stats("ip-b", now=base + MIN_SAMPLES_FOR_IP * 60)

        assert stats_a.mean < stats_b.mean
        assert stats_a.is_cold is False
        assert stats_b.is_cold is False

    def test_tracked_ip_count(self):
        window = SlidingWindow(window_seconds=60)
        engine = BaselineEngine(window)
        base = 100_000.0

        for ip_n in range(5):
            window.record(f"10.0.0.{ip_n}", make_ts(base - 1))
        engine.recalculate(now=base)

        assert engine.tracked_ip_count() == 5
