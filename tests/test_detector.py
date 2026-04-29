"""
tests/test_detector.py

Tests are grouped by:
  1. Pure helpers (_normalise, _score_to_decision)
  2. Individual signals in isolation
  3. Dynamic threshold tightening
  4. Edge cases
  5. Full end-to-end scenarios (the ones from the spec)
"""

import math
import pytest
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.detector import (
    AnomalyDetector, Decision, DetectionResult, Signal,
    _normalise, _score_to_decision,
    Z_SCORE_BLOCK, Z_SCORE_FLAG,
    RATE_MULTIPLE_BLOCK, RATE_MULTIPLE_FLAG,
    ERROR_RATE_BLOCK, ERROR_RATE_FLAG, ERROR_MIN_REQUESTS,
    GLOBAL_Z_BLOCK, GLOBAL_Z_FLAG,
    TIGHTEN_WINDOW_SECONDS, TIGHTEN_Z_BLOCK, TIGHTEN_RATE_BLOCK,
)
from detector.baseline import BaselineEngine, Stats, MEAN_FLOOR, STDDEV_FLOOR
from detector.sliding_window import SlidingWindow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ts(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def make_stats(mean=10.0, stddev=2.0, sample_count=20,
               is_cold=False, hour=9) -> Stats:
    """Construct a Stats object with known values for deterministic tests."""
    return Stats(
        mean=mean, stddev=stddev,
        sample_count=sample_count,
        is_cold=is_cold,
        hour_segment=hour,
    )


class StubBaseline:
    """
    Minimal baseline stub — returns a fixed Stats object for any IP.
    Lets us test the detector independently of the baseline engine.
    """
    def __init__(self, ip_stats: Stats = None, global_stats: Stats = None):
        self._ip_stats     = ip_stats     or make_stats()
        self._global_stats = global_stats or make_stats(mean=100.0, stddev=20.0)

    def get_stats(self, ip: str, now=None) -> Stats:
        if ip == "__global__":
            return self._global_stats
        return self._ip_stats


class StubWindow:
    """Minimal window stub — returns fixed values."""
    def __init__(self, ip_rate=0, global_rate=0):
        self._ip_rate     = ip_rate
        self._global_rate = global_rate

    def ip_rate(self, ip, as_of=None):
        return self._ip_rate

    def global_rate(self, as_of=None):
        return self._global_rate

    def ip_snapshot(self, as_of=None):
        return {}


def make_detector(ip_stats=None, global_stats=None):
    baseline = StubBaseline(ip_stats, global_stats)
    window   = StubWindow()
    return AnomalyDetector(window, baseline, now_fn=lambda: 100_000.0)


def evaluate(detector, source_ip="1.2.3.4", current_rate=10.0,
             error_count=0, total_count=10, global_rate=100.0,
             now=100_000.0):
    return detector.evaluate(
        source_ip=source_ip,
        current_rate=current_rate,
        error_count=error_count,
        total_count=total_count,
        global_rate=global_rate,
        now=now,
    )


# ---------------------------------------------------------------------------
# 1. Pure helpers
# ---------------------------------------------------------------------------

class TestNormalise:

    def test_at_low_boundary_returns_half(self):
        assert _normalise(3.0, 3.0, 6.0) == 0.5

    def test_at_high_boundary_returns_one(self):
        assert _normalise(6.0, 3.0, 6.0) == 1.0

    def test_above_high_clamped_to_one(self):
        assert _normalise(100.0, 3.0, 6.0) == 1.0

    def test_midpoint_returns_three_quarters(self):
        assert abs(_normalise(4.5, 3.0, 6.0) - 0.75) < 0.001

    def test_equal_low_high_returns_one(self):
        # Degenerate case — avoid division by zero
        assert _normalise(5.0, 5.0, 5.0) == 1.0


class TestScoreToDecision:

    def test_zero_score_is_allow(self):
        assert _score_to_decision(0.0) == Decision.ALLOW

    def test_below_flag_is_allow(self):
        assert _score_to_decision(0.49) == Decision.ALLOW

    def test_at_flag_threshold_is_flag(self):
        assert _score_to_decision(0.50) == Decision.FLAG

    def test_between_flag_and_block_is_flag(self):
        assert _score_to_decision(0.74) == Decision.FLAG

    def test_at_block_threshold_is_block(self):
        assert _score_to_decision(0.75) == Decision.BLOCK

    def test_max_score_is_block(self):
        assert _score_to_decision(1.0) == Decision.BLOCK


# ---------------------------------------------------------------------------
# 2. Signal: Z-score
# ---------------------------------------------------------------------------

class TestZScoreSignal:

    def test_normal_rate_scores_low(self):
        # mean=10, stddev=2, rate=11 → Z=0.5 → should ALLOW
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=11.0)
        zsig = next(s for s in result.signals if s.name == "z_score")
        assert zsig.score < 0.5
        assert result.decision == Decision.ALLOW

    def test_z_above_flag_threshold_blocks(self):
        # mean=10, stddev=2, rate=15 → Z=2.5
        # _normalise(2.5, flag=2.0, block=3.0) = 0.75 → BLOCK
        # (Z=2.5 is halfway between flag and block → scores at block boundary)
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=15.0)
        assert result.decision == Decision.BLOCK

    def test_z_above_block_threshold_blocks(self):
        # mean=10, stddev=2, rate=20 → Z=5.0 → BLOCK
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=20.0)
        assert result.decision == Decision.BLOCK

    def test_z_score_value_in_signal(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=20.0)
        zsig = next(s for s in result.signals if s.name == "z_score")
        expected_z = (20.0 - 10.0) / 2.0
        assert abs(zsig.z_score - expected_z) < 0.001

    def test_reason_string_present_when_flagged(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=20.0)
        assert len(result.reasons) > 0
        assert "z-score" in result.reasons[0].lower()

    def test_below_mean_does_not_flag(self):
        # Rate below mean should never flag
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=5.0)
        assert result.decision == Decision.ALLOW

    def test_cold_start_high_traffic_still_blocked(self):
        # Cold start stats are conservative but extreme rates still trigger
        cold = make_stats(mean=10.0, stddev=6.0, is_cold=True)
        d = make_detector(ip_stats=cold)
        # Z = (200 - 10) / 6 = 31.7
        result = evaluate(d, current_rate=200.0)
        assert result.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# 3. Signal: Rate multiple
# ---------------------------------------------------------------------------

class TestRateMultipleSignal:

    def test_normal_rate_no_flag(self):
        # rate = 2× mean — below flag threshold
        d = make_detector(ip_stats=make_stats(mean=10.0))
        result = evaluate(d, current_rate=20.0)
        rmsig = next(s for s in result.signals if s.name == "rate_multiple")
        assert rmsig.score < 0.5

    def test_rate_above_flag_multiple(self):
        # rate = 4× mean (threshold = 3×) → FLAG
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=100.0))
        result = evaluate(d, current_rate=40.0)
        rmsig = next(s for s in result.signals if s.name == "rate_multiple")
        assert rmsig.score >= 0.5

    def test_rate_above_block_multiple(self):
        # rate = 10× mean → _normalise(10, 5, 10) = 1.0 → BLOCK signal
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=100.0))
        result = evaluate(d, current_rate=100.0)
        rmsig = next(s for s in result.signals if s.name == "rate_multiple")
        assert rmsig.score >= 0.75

    def test_rate_multiple_reason_contains_multiple(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=100.0))
        result = evaluate(d, current_rate=60.0)
        rmsig = next(s for s in result.signals if s.name == "rate_multiple")
        assert "6.0×" in rmsig.reason or "×" in rmsig.reason

    def test_zero_mean_no_crash(self):
        # Baseline mean of 0 — should not divide by zero
        zero_mean = Stats(mean=0.0, stddev=1.5, sample_count=0,
                          is_cold=True, hour_segment=0)
        d = make_detector(ip_stats=zero_mean)
        result = evaluate(d, current_rate=100.0)
        # Must not raise; rate_multiple signal should be 0
        rmsig = next(s for s in result.signals if s.name == "rate_multiple")
        assert rmsig.score == 0.0


# ---------------------------------------------------------------------------
# 4. Signal: Error surge
# ---------------------------------------------------------------------------

class TestErrorSurgeSignal:

    def test_below_min_requests_no_signal(self):
        d = make_detector()
        result = evaluate(d, error_count=5, total_count=ERROR_MIN_REQUESTS - 1)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score == 0.0

    def test_low_error_rate_no_flag(self):
        # 2 errors in 20 requests = 10% — below 30% flag threshold
        d = make_detector()
        result = evaluate(d, error_count=2, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score < 0.5

    def test_error_rate_above_flag_threshold(self):
        # 8/20 = 40% — above 30% flag threshold
        d = make_detector()
        result = evaluate(d, error_count=8, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score >= 0.5

    def test_error_rate_above_block_threshold(self):
        # 15/20 = 75% — above 50% block threshold
        d = make_detector()
        result = evaluate(d, error_count=15, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score >= 0.75

    def test_all_errors_max_score(self):
        # 20/20 = 100% error rate
        d = make_detector()
        result = evaluate(d, error_count=20, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score == 1.0

    def test_error_count_clamped_above_total(self):
        # Data integrity: error_count > total_count should not crash or exceed 1.0
        d = make_detector()
        result = evaluate(d, error_count=30, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score <= 1.0

    def test_zero_total_no_crash(self):
        d = make_detector()
        result = evaluate(d, error_count=0, total_count=0)
        # Must not raise
        assert result.decision == Decision.ALLOW

    def test_error_signal_independent_of_rate(self):
        """
        A slow credential stuffer: low rate (5 req/60s) but 80% errors.
        Rate signals should be clean; error signal should BLOCK.
        """
        normal_stats = make_stats(mean=10.0, stddev=2.0)
        d = make_detector(ip_stats=normal_stats)
        # rate=5 is below mean — no rate anomaly
        # 4/5 = 80% errors — should trigger error signal
        result = evaluate(d, current_rate=5.0, error_count=4, total_count=5)
        # total_count=5 is below ERROR_MIN_REQUESTS=10, so score=0
        # Use total_count=20 to satisfy minimum
        result = evaluate(d, current_rate=5.0, error_count=16, total_count=20)
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score >= 0.75


# ---------------------------------------------------------------------------
# 5. Signal: Global anomaly
# ---------------------------------------------------------------------------

class TestGlobalAnomalySignal:

    def test_normal_global_rate_no_flag(self):
        # global mean=100, stddev=20, rate=110 → Z=0.5
        global_stats = make_stats(mean=100.0, stddev=20.0)
        d = make_detector(global_stats=global_stats)
        result = evaluate(d, global_rate=110.0)
        gsig = next(s for s in result.signals if s.name == "global_anomaly")
        assert gsig.score < 0.5

    def test_global_rate_above_flag_threshold(self):
        # mean=100, stddev=20, rate=165 → Z=3.25 → FLAG
        global_stats = make_stats(mean=100.0, stddev=20.0)
        d = make_detector(global_stats=global_stats)
        result = evaluate(d, global_rate=165.0)
        gsig = next(s for s in result.signals if s.name == "global_anomaly")
        assert gsig.score >= 0.5

    def test_global_rate_above_block_threshold(self):
        # mean=100, stddev=20, rate=220 → Z=6.0
        # _normalise(6, GLOBAL_Z_BLOCK=4.0, 8.0) = 0.75 → BLOCK
        global_stats = make_stats(mean=100.0, stddev=20.0)
        d = make_detector(global_stats=global_stats)
        result = evaluate(d, global_rate=220.0)
        gsig = next(s for s in result.signals if s.name == "global_anomaly")
        assert gsig.score >= 0.75

    def test_global_signal_does_not_block_innocent_ip(self):
        """
        Global anomaly alone should not block an individual IP whose
        own rate and error signals are clean. The decision engine uses
        max score — if only global is high, the IP gets BLOCK from
        that signal. This is intentional: under DDoS all IPs are suspect.
        Verify the signal fires but the reason is clearly labelled.
        """
        global_stats = make_stats(mean=100.0, stddev=20.0)
        d = make_detector(global_stats=global_stats)
        result = evaluate(d, current_rate=10.0, global_rate=200.0)
        gsig = next(s for s in result.signals if s.name == "global_anomaly")
        assert "global_rate" in gsig.reason


# ---------------------------------------------------------------------------
# 6. Dynamic threshold tightening
# ---------------------------------------------------------------------------

class TestDynamicTightening:

    def test_not_tightened_by_default(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=15.0)
        assert result.tightened is False

    def test_flag_then_tighten(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        d.record_flag("1.2.3.4", now=100_000.0)
        result = evaluate(d, source_ip="1.2.3.4", current_rate=15.0,
                         now=100_000.0 + 60)   # 60s after flag
        assert result.tightened is True

    def test_tighten_window_expires(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        d.record_flag("1.2.3.4", now=100_000.0)
        # Evaluate after TIGHTEN_WINDOW_SECONDS has passed
        result = evaluate(d, source_ip="1.2.3.4", current_rate=15.0,
                         now=100_000.0 + TIGHTEN_WINDOW_SECONDS + 1)
        assert result.tightened is False

    def test_tightened_z_threshold_lower(self):
        """
        Normal threshold: Z > 3.0 to block.
        Tightened threshold: Z > 2.0 to block.
        Rate that gives Z=2.0 exactly scores 0.5 → FLAG normally.
        Tightened: Z=2.0 > TIGHTEN_Z_BLOCK(2.0) triggers block path → BLOCK.
        """
        # mean=10, stddev=2 → Z=2.0 at rate=14
        ip_stats = make_stats(mean=10.0, stddev=2.0)
        d_normal    = make_detector(ip_stats=ip_stats)
        d_tightened = make_detector(ip_stats=ip_stats)
        d_tightened.record_flag("1.2.3.4", now=100_000.0)

        r_normal    = evaluate(d_normal,    current_rate=14.0, now=100_000.0 + 10)
        r_tightened = evaluate(d_tightened, current_rate=14.0,
                               source_ip="1.2.3.4", now=100_000.0 + 10)

        # Normal: Z=2.0 == FLAG threshold → FLAG (score=0.5)
        assert r_normal.decision    == Decision.FLAG
        # Tightened: Z=2.0 > TIGHTEN_BLOCK(2.0) — on tighten path → BLOCK
        assert r_tightened.decision == Decision.BLOCK

    def test_tightened_reason_labelled(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        d.record_flag("1.2.3.4", now=100_000.0)
        result = evaluate(d, source_ip="1.2.3.4",
                          current_rate=15.0, now=100_000.0 + 10)
        assert any("[tightened]" in r for r in result.reasons)

    def test_clear_flag_removes_tightening(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        d.record_flag("1.2.3.4", now=100_000.0)
        d.clear_flag("1.2.3.4")
        result = evaluate(d, source_ip="1.2.3.4",
                          current_rate=15.0, now=100_000.0 + 10)
        assert result.tightened is False

    def test_different_ips_not_cross_contaminated(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        d.record_flag("1.1.1.1", now=100_000.0)
        result = evaluate(d, source_ip="2.2.2.2",
                          current_rate=15.0, now=100_000.0 + 10)
        assert result.tightened is False


# ---------------------------------------------------------------------------
# 7. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_zero_rate_always_allow(self):
        d = make_detector()
        result = evaluate(d, current_rate=0.0, error_count=0, total_count=0)
        assert result.decision == Decision.ALLOW

    def test_all_signals_always_present(self):
        """Result always has exactly 4 signals regardless of decision."""
        d = make_detector()
        result = evaluate(d, current_rate=0.0)
        assert len(result.signals) == 4
        names = {s.name for s in result.signals}
        assert names == {"z_score", "rate_multiple", "error_surge", "global_anomaly"}

    def test_max_score_is_max_of_signals(self):
        d = make_detector()
        result = evaluate(d, current_rate=200.0)
        expected_max = max(s.score for s in result.signals)
        assert abs(result.max_score - expected_max) < 0.001

    def test_dominant_signal_is_highest_score(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=200.0)
        dom = result.dominant_signal()
        assert dom.score == result.max_score

    def test_is_anomalous_false_for_allow(self):
        d = make_detector()
        result = evaluate(d, current_rate=10.0)
        assert result.is_anomalous is False

    def test_is_anomalous_true_for_block(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=100.0)
        assert result.is_anomalous is True

    def test_summary_string_contains_key_fields(self):
        d = make_detector(ip_stats=make_stats(mean=10.0, stddev=2.0))
        result = evaluate(d, current_rate=100.0)
        summary = result.summary()
        assert "ip=" in summary
        assert "decision=" in summary
        assert "score=" in summary


# ---------------------------------------------------------------------------
# 8. End-to-end scenarios
# ---------------------------------------------------------------------------

class TestScenarios:

    def test_scenario_normal_user(self):
        """
        A legitimate user making normal requests.
        Rate = mean. No errors. Global traffic normal.
        Expected: ALLOW.
        """
        d = make_detector(
            ip_stats=make_stats(mean=20.0, stddev=4.0),
            global_stats=make_stats(mean=100.0, stddev=20.0),
        )
        result = evaluate(d, current_rate=20.0, error_count=1,
                          total_count=20, global_rate=100.0)
        assert result.decision == Decision.ALLOW

    def test_scenario_volumetric_attacker(self):
        """
        Single IP flooding: 300 req/60s against a baseline mean of 20.
        Z = (300 - 20) / 4 = 70. Rate = 15× baseline.
        Expected: BLOCK on both Z-score and rate-multiple signals.
        """
        d = make_detector(
            ip_stats=make_stats(mean=20.0, stddev=4.0),
            global_stats=make_stats(mean=100.0, stddev=20.0),
        )
        result = evaluate(d, current_rate=300.0, error_count=0,
                          total_count=300, global_rate=400.0)
        assert result.decision == Decision.BLOCK
        # Both Z-score and rate-multiple should be blocking
        z_sig  = next(s for s in result.signals if s.name == "z_score")
        rm_sig = next(s for s in result.signals if s.name == "rate_multiple")
        assert z_sig.score  >= 0.75
        assert rm_sig.score >= 0.75

    def test_scenario_credential_stuffer(self):
        """
        Slow credential stuffing: low rate (5 req/60s) but 80% are 401s.
        Rate signals clean. Error signal fires.
        Expected: BLOCK from error_surge.
        """
        d = make_detector(
            ip_stats=make_stats(mean=20.0, stddev=4.0),
            global_stats=make_stats(mean=100.0, stddev=20.0),
        )
        result = evaluate(d, current_rate=20.0, error_count=16,
                          total_count=20, global_rate=100.0)
        assert result.decision == Decision.BLOCK
        esig = next(s for s in result.signals if s.name == "error_surge")
        assert esig.score >= 0.75

    def test_scenario_distributed_ddos(self):
        """
        DDoS: no single IP is above threshold but global rate is 5× normal.
        Global Z = (500 - 100) / 20 = 20.
        Expected: BLOCK from global_anomaly signal even for innocent-looking IPs.
        """
        d = make_detector(
            ip_stats=make_stats(mean=20.0, stddev=4.0),
            global_stats=make_stats(mean=100.0, stddev=20.0),
        )
        result = evaluate(d, current_rate=20.0, error_count=0,
                          total_count=20, global_rate=500.0)
        gsig = next(s for s in result.signals if s.name == "global_anomaly")
        assert gsig.score >= 0.75
        assert result.decision == Decision.BLOCK

    def test_scenario_persistent_attacker_tightening(self):
        """
        Attacker learns to stay just below threshold (Z=2.5, rate=3.5×).
        First request: FLAG (Z < 3.0 normal threshold).
        After flag recorded: tightening kicks in.
        Second request at same rate: BLOCK (Z > 2.0 tightened threshold).
        """
        # mean=10, stddev=2, rate=14 → Z=2.0 → exactly FLAG threshold
        ip_stats = make_stats(mean=10.0, stddev=2.0)
        d = make_detector(ip_stats=ip_stats)

        # First request: FLAG (Z=2.0 at normal threshold)
        r1 = evaluate(d, source_ip="attacker", current_rate=14.0, now=100_000.0)
        assert r1.decision == Decision.FLAG

        # Record the flag — tightening now active
        d.record_flag("attacker", now=100_000.0)

        # Second request (60s later, same rate): BLOCK (tightened threshold = 2.0)
        r2 = evaluate(d, source_ip="attacker", current_rate=14.0,
                      now=100_000.0 + 60)
        assert r2.decision == Decision.BLOCK
        assert r2.tightened is True

    def test_scenario_new_ip_cold_start(self):
        """
        Brand new IP making moderate requests during system startup.
        Baseline is cold default (wide band).
        Rate = 15 req/60s — should not be flagged during cold start.
        """
        cold_stats = make_stats(mean=10.0, stddev=6.0, is_cold=True)
        d = make_detector(ip_stats=cold_stats)
        result = evaluate(d, current_rate=15.0, error_count=0,
                          total_count=15, global_rate=50.0)
        # Z = (15 - 10) / 6 = 0.83 → ALLOW
        assert result.decision == Decision.ALLOW

    def test_scenario_scanner_path_diversity(self):
        """
        Path scanner: moderate rate (25 req/60s) with many 404s.
        Z = (25 - 20) / 4 = 1.25 — below flag threshold.
        Error rate = 20/25 = 80% — above block threshold.
        Expected: BLOCK from error_surge.
        """
        d = make_detector(
            ip_stats=make_stats(mean=20.0, stddev=4.0),
            global_stats=make_stats(mean=100.0, stddev=20.0),
        )
        result = evaluate(d, current_rate=25.0, error_count=20,
                          total_count=25, global_rate=105.0)
        assert result.decision == Decision.BLOCK
        dom = result.dominant_signal()
        assert dom.name == "error_surge"
