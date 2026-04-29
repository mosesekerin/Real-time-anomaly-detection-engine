"""
detector/detector.py — Anomaly detection logic.

Contract:
  Input:  LogEntry + current SlidingWindow state + BaselineEngine stats
  Output: DetectionResult (decision + scores + reasons)

This module makes NO external calls. No Redis, no file IO, no HTTP.
It is a pure decision engine: given the current state of the world,
what should happen to this request?

Detection signals (four, independent):
  1. Z-score        — how many stddevs above baseline is this IP's rate?
  2. Rate multiple  — is the raw rate > N × baseline mean?
  3. Error surge    — is this IP generating an abnormal 4xx/5xx ratio?
  4. Global anomaly — is the ENTIRE system under load? (DDoS signal)

Thresholds:
  Z-score > 3.0 → anomalous
  Rate   > 5× mean → anomalous
  Error rate > 0.5 with >= 10 recent requests → anomalous
  Global Z-score > 4.0 → system-wide alert

Dynamic tightening:
  If an IP was flagged in the last TIGHTEN_WINDOW_SECONDS, thresholds
  drop — Z > 2.0 and rate > 3× become sufficient to escalate to BLOCK.
  This prevents a persistent attacker from staying just below threshold.
"""

import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Primary thresholds
Z_SCORE_BLOCK          = 3.0   # Z > this → BLOCK
Z_SCORE_FLAG           = 2.0   # Z > this → FLAG
RATE_MULTIPLE_BLOCK    = 5.0   # rate > N × mean → BLOCK
RATE_MULTIPLE_FLAG     = 3.0   # rate > N × mean → FLAG

# Error surge thresholds
ERROR_RATE_BLOCK       = 0.50  # 50% of requests are errors → BLOCK
ERROR_RATE_FLAG        = 0.30  # 30% of requests are errors → FLAG
ERROR_MIN_REQUESTS     = 10    # minimum requests before error rate is trusted

# Global anomaly threshold (Z-score on total system traffic)
GLOBAL_Z_BLOCK         = 4.0   # higher threshold — global spikes are normal
GLOBAL_Z_FLAG          = 3.0

# Dynamic tightening — applied when an IP was recently flagged
TIGHTEN_WINDOW_SECONDS = 300   # 5 minutes
TIGHTEN_Z_BLOCK        = 2.0   # tightened Z threshold
TIGHTEN_RATE_BLOCK     = 3.0   # tightened rate multiple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Decision(Enum):
    ALLOW = "allow"
    FLAG  = "flag"
    BLOCK = "block"


@dataclass
class Signal:
    """One scored detection signal with its contributing reason."""
    name:    str
    score:   float          # 0.0 = clean, 1.0 = maximum anomaly
    z_score: Optional[float] = None
    value:   Optional[float] = None   # the raw measured value (rate, ratio, etc.)
    reason:  str = ""


@dataclass
class DetectionResult:
    """
    Full detection output for one request.

    Consumed by blocker.py and notifier.py.
    Never raises — always returns a valid result.
    """
    source_ip:    str
    decision:     Decision
    max_score:    float                  # highest signal score (0.0–1.0)
    signals:      list[Signal]           # all four signals, always present
    reasons:      list[str]              # human-readable summary of triggers
    tightened:    bool                   # True if dynamic tightening was applied
    timestamp:    float = field(default_factory=time.time)

    @property
    def is_anomalous(self) -> bool:
        return self.decision != Decision.ALLOW

    def dominant_signal(self) -> Signal:
        """The signal with the highest score."""
        return max(self.signals, key=lambda s: s.score)

    def summary(self) -> str:
        return (
            f"ip={self.source_ip} decision={self.decision.value} "
            f"score={self.max_score:.2f} "
            f"dominant={self.dominant_signal().name} "
            f"tightened={self.tightened} "
            f"reasons={self.reasons}"
        )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Stateless per-request anomaly detector.

    'Stateless' means it reads state (from window + baseline) but never
    writes state. Writing state (blocklist, flag history) is the
    blocker's job.

    Usage:
        detector = AnomalyDetector(sliding_window, baseline_engine)

        # Called by monitor handler on every parsed log entry:
        result = detector.evaluate(entry)
        if result.decision == Decision.BLOCK:
            blocker.block(result.source_ip)
    """

    def __init__(self, sliding_window, baseline_engine, now_fn=None):
        self._window   = sliding_window
        self._baseline = baseline_engine
        self._now      = now_fn or time.time

        # flag_history: ip → unix timestamp of last flag/block
        # Written by record_flag(), read by _is_tightened()
        # In production this would be Redis. Here it is in-process
        # so the detector remains independently testable.
        self._flag_history: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public: main evaluation entry point
    # ------------------------------------------------------------------

    def evaluate(
        self,
        source_ip:    str,
        current_rate: float,        # requests from this IP in last 60s
        error_count:  int,          # 4xx/5xx from this IP in last 60s
        total_count:  int,          # total requests from this IP in last 60s
        global_rate:  float,        # total requests across all IPs in last 60s
        now:          Optional[float] = None,
    ) -> DetectionResult:
        """
        Evaluate one request context and return a DetectionResult.

        Args:
            source_ip:    Client IP string.
            current_rate: How many requests this IP made in the last 60s.
            error_count:  How many of those were 4xx or 5xx.
            total_count:  Same as current_rate (kept separate for clarity —
                          in future you may count differently e.g. unique paths).
            global_rate:  Total requests across ALL IPs in last 60s.
            now:          Unix timestamp. Defaults to time.time().

        Returns:
            DetectionResult with decision, all signal scores, and reasons.
        """
        now = now if now is not None else self._now()

        # Fetch baselines for this IP and for the global population
        ip_stats     = self._baseline.get_stats(source_ip, now=now)
        global_stats = self._baseline.get_stats("__global__", now=now)

        # Is this IP under tightened thresholds?
        tightened = self._is_tightened(source_ip, now)

        # Evaluate all four signals independently
        sig_zscore  = self._signal_zscore(current_rate, ip_stats, tightened)
        sig_rate    = self._signal_rate_multiple(current_rate, ip_stats, tightened)
        sig_errors  = self._signal_error_surge(error_count, total_count)
        sig_global  = self._signal_global_anomaly(global_rate, global_stats)

        signals = [sig_zscore, sig_rate, sig_errors, sig_global]

        # Decision: max score across all signals
        max_score = max(s.score for s in signals)
        decision  = _score_to_decision(max_score)

        # Collect human-readable reasons for all triggered signals
        reasons = [s.reason for s in signals if s.reason]

        result = DetectionResult(
            source_ip=source_ip,
            decision=decision,
            max_score=max_score,
            signals=signals,
            reasons=reasons,
            tightened=tightened,
            timestamp=now,
        )

        if result.is_anomalous:
            logger.warning("ANOMALY | %s", result.summary())

        return result

    def record_flag(self, source_ip: str, now: Optional[float] = None) -> None:
        """
        Record that this IP was flagged or blocked.
        Called by the blocker after acting on a DetectionResult.
        Enables dynamic threshold tightening on subsequent requests.
        """
        now = now if now is not None else self._now()
        self._flag_history[source_ip] = now

    def clear_flag(self, source_ip: str) -> None:
        """Clear flag history for an IP (called by unbanner)."""
        self._flag_history.pop(source_ip, None)

    # ------------------------------------------------------------------
    # Internal: signal evaluators
    # ------------------------------------------------------------------

    def _signal_zscore(
        self,
        current_rate: float,
        ip_stats,
        tightened: bool,
    ) -> Signal:
        """
        Signal 1: Z-score on this IP's request rate vs its own baseline.

        Z = (current_rate - mean) / stddev

        The baseline stddev floor ensures we never divide by zero and
        that low-traffic IPs get a reasonable band.

        Tightening: if this IP was recently flagged, Z > 2.0 blocks
        instead of the normal Z > 3.0.
        """
        z = ip_stats.z_score(current_rate)

        block_threshold = TIGHTEN_Z_BLOCK if tightened else Z_SCORE_BLOCK
        flag_threshold  = Z_SCORE_FLAG

        if z > block_threshold:
            score  = _normalise(z, block_threshold, block_threshold * 2)
            reason = (
                f"z-score={z:.2f} exceeds block threshold={block_threshold:.1f}"
                f" (mean={ip_stats.mean:.1f}, stddev={ip_stats.stddev:.1f})"
                + (" [tightened]" if tightened else "")
            )
        elif z > flag_threshold:
            score  = _normalise(z, flag_threshold, block_threshold)
            reason = (
                f"z-score={z:.2f} exceeds flag threshold={flag_threshold:.1f}"
            )
        else:
            score  = max(0.0, z / block_threshold)
            reason = ""

        return Signal(
            name="z_score",
            score=min(score, 1.0),
            z_score=z,
            value=current_rate,
            reason=reason,
        )

    def _signal_rate_multiple(
        self,
        current_rate: float,
        ip_stats,
        tightened: bool,
    ) -> Signal:
        """
        Signal 2: Raw rate as a multiple of the baseline mean.

        Why this signal in addition to Z-score?
        Z-score is relative to variance. An IP with high natural variance
        (stddev=50) could send 500 req/min (10× normal) and get Z=5 — caught.
        But an IP with low variance (stddev=0.5, floor-adjusted to 1.5) sending
        20 req/min gets Z=(20-2)/1.5=12 — also caught, but the RATE MULTIPLE
        catches it independently and provides a more intuitive reason string.

        Also, during cold start when is_cold=True, the baseline mean is a
        population default (10.0). A new IP sending 60 req/min gets
        Z=(60-10)/6=8.3 (caught by Z-score) but also rate=6× mean (caught here).
        Both signals fire — belt AND suspenders.

        Tightening: 3× instead of 5× sufficient to block.
        """
        if ip_stats.mean <= 0:
            return Signal(name="rate_multiple", score=0.0, reason="")

        multiple = current_rate / ip_stats.mean

        block_threshold = TIGHTEN_RATE_BLOCK if tightened else RATE_MULTIPLE_BLOCK
        flag_threshold  = RATE_MULTIPLE_FLAG

        if multiple > block_threshold:
            score  = _normalise(multiple, block_threshold, block_threshold * 2)
            reason = (
                f"rate={current_rate:.0f} is {multiple:.1f}× baseline mean={ip_stats.mean:.1f}"
                f" (block at {block_threshold:.0f}×)"
                + (" [tightened]" if tightened else "")
            )
        elif multiple > flag_threshold:
            score  = _normalise(multiple, flag_threshold, block_threshold)
            reason = (
                f"rate={current_rate:.0f} is {multiple:.1f}× baseline mean={ip_stats.mean:.1f}"
            )
        else:
            score  = max(0.0, (multiple - 1.0) / block_threshold)
            reason = ""

        return Signal(
            name="rate_multiple",
            score=min(score, 1.0),
            value=multiple,
            reason=reason,
        )

    def _signal_error_surge(
        self,
        error_count: int,
        total_count: int,
    ) -> Signal:
        """
        Signal 3: 4xx/5xx error ratio for this IP.

        Why a separate signal?
        Z-score and rate-multiple only look at volume. A slow brute-force
        attack or a credential-stuffing scanner may stay well below rate
        thresholds but generate a high error ratio (many 401s/403s/404s).
        This signal catches that pattern.

        Edge cases:
          - total_count < ERROR_MIN_REQUESTS → score=0 (not enough data)
          - total_count == 0 → score=0 (no requests, no signal)
          - error_count > total_count → clamped to 1.0 (data integrity guard)
        """
        if total_count < ERROR_MIN_REQUESTS:
            return Signal(
                name="error_surge",
                score=0.0,
                reason="",
                value=0.0,
            )

        error_rate = min(error_count / total_count, 1.0)

        if error_rate >= ERROR_RATE_BLOCK:
            score  = _normalise(error_rate, ERROR_RATE_BLOCK, 1.0)
            reason = (
                f"error_rate={error_rate:.0%} ({error_count}/{total_count} requests)"
                f" exceeds block threshold={ERROR_RATE_BLOCK:.0%}"
            )
        elif error_rate >= ERROR_RATE_FLAG:
            score  = _normalise(error_rate, ERROR_RATE_FLAG, ERROR_RATE_BLOCK)
            reason = (
                f"error_rate={error_rate:.0%} ({error_count}/{total_count} requests)"
                f" exceeds flag threshold={ERROR_RATE_FLAG:.0%}"
            )
        else:
            score  = error_rate / ERROR_RATE_BLOCK
            reason = ""

        return Signal(
            name="error_surge",
            score=min(score, 1.0),
            value=error_rate,
            reason=reason,
        )

    def _signal_global_anomaly(
        self,
        global_rate:  float,
        global_stats,
    ) -> Signal:
        """
        Signal 4: Z-score on total system traffic.

        This signal does NOT block individual IPs — it is a system-level
        indicator. When the global Z-score is high, it means the entire
        server is under load (DDoS, flash crowd, or bot swarm).

        The blocker uses this signal to enable rate-limiting for ALL IPs,
        not just the ones with high individual scores. This is out of scope
        for the detector — here we just score it.

        Higher threshold (4.0) than per-IP (3.0) because global traffic
        naturally varies more than per-IP traffic.
        """
        z = global_stats.z_score(global_rate)

        if z > GLOBAL_Z_BLOCK:
            score  = _normalise(z, GLOBAL_Z_BLOCK, GLOBAL_Z_BLOCK * 2)
            reason = (
                f"global_rate={global_rate:.0f} is {z:.1f}σ above system baseline"
                f" (mean={global_stats.mean:.1f})"
            )
        elif z > GLOBAL_Z_FLAG:
            score  = _normalise(z, GLOBAL_Z_FLAG, GLOBAL_Z_BLOCK)
            reason = f"global_rate={global_rate:.0f} is elevated ({z:.1f}σ)"
        else:
            score  = max(0.0, z / GLOBAL_Z_BLOCK)
            reason = ""

        return Signal(
            name="global_anomaly",
            score=min(score, 1.0),
            z_score=z,
            value=global_rate,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Internal: tightening
    # ------------------------------------------------------------------

    def _is_tightened(self, source_ip: str, now: float) -> bool:
        """
        Returns True if this IP was flagged/blocked within TIGHTEN_WINDOW_SECONDS.

        Effect: Z_SCORE_BLOCK drops from 3.0 → 2.0
                RATE_MULTIPLE_BLOCK drops from 5× → 3×

        Why: a persistent attacker who learns to stay just below the 3.0
        threshold gets NO benefit of the doubt on their next attempt within
        the tighten window.
        """
        last_flag = self._flag_history.get(source_ip)
        if last_flag is None:
            return False
        return (now - last_flag) < TIGHTEN_WINDOW_SECONDS


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def _score_to_decision(score: float) -> Decision:
    """
    Map a normalised score (0.0–1.0) to a Decision.

    Score bands:
      0.00–0.49 → ALLOW  (below flag threshold)
      0.50–0.74 → FLAG   (anomalous, monitor, optionally challenge)
      0.75–1.00 → BLOCK  (clearly anomalous, reject)

    Why 0.75 for block and not 1.0?
    A score of 1.0 means "exactly at the upper bound of the normalisation
    range". In practice scores above 0.75 already represent clear anomalies
    (Z > 3.0, or rate > 5×). Waiting for a perfect 1.0 would delay action.
    """
    if score >= 0.75:
        return Decision.BLOCK
    if score >= 0.50:
        return Decision.FLAG
    return Decision.ALLOW


def _normalise(value: float, low: float, high: float) -> float:
    """
    Map value from [low, high] to [0.5, 1.0].

    Why 0.5 as the floor?
    Any value at or above `low` already crossed a threshold (flag or block).
    The minimum normalised score for a triggered threshold is 0.5 — meaning
    "at least FLAG". Values approaching `high` map toward 1.0 (BLOCK).

    Values above `high` are clamped to 1.0.
    """
    if high <= low:
        return 1.0
    ratio = (value - low) / (high - low)
    return 0.5 + 0.5 * min(ratio, 1.0)
