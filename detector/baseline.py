"""
detector/baseline.py — Rolling per-IP and global request rate baseline.

Responsibilities:
  - Maintain a 30-minute history of per-second request counts per IP
  - Recalculate mean and stddev every 60 seconds
  - Apply floor values to prevent low-traffic false positives
  - Segment baselines by hour-of-day (9am vs 3am are different patterns)
  - Handle cold start safely with a conservative fallback

Architecture — why 60-second samples over 30 minutes?
  The sliding window already tracks raw timestamps.
  Every 60s we sample the current 60s count → one data point.
  30 minutes = 30 samples. Enough for stable stats, minimal memory.
"""

import math
import time
import logging
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HISTORY_SAMPLES        = 30    # 30 min × 1 sample/min
RECALC_INTERVAL        = 60    # seconds between recalculations
MEAN_FLOOR             = 2.0   # minimum usable mean (req/60s)
STDDEV_FLOOR           = 1.5   # minimum usable stddev
MIN_SAMPLES_FOR_IP     = 5     # samples needed before trusting per-IP stats
HOURS_IN_DAY           = 24


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Stats:
    """
    Baseline statistics for one IP at one moment.
    Consumed by detector.py to compute Z-scores.
    All fields are finite and positive — never NaN, inf, or zero stddev.
    """
    mean:         float
    stddev:       float
    sample_count: int
    is_cold:      bool   # True = using population fallback, not IP-specific data
    hour_segment: int    # 0-23

    def z_score(self, current_rate: float) -> float:
        """Z = (x - mean) / stddev. Safe — stddev is always > 0."""
        return (current_rate - self.mean) / self.stddev


@dataclass
class _IPHistory:
    samples:      deque = field(default_factory=lambda: deque(maxlen=HISTORY_SAMPLES))
    cached_stats: Optional[Stats] = None
    last_recalc:  float = 0.0


# ---------------------------------------------------------------------------
# Baseline engine
# ---------------------------------------------------------------------------

class BaselineEngine:
    """
    Maintains rolling per-IP and global baselines.

    recalculate() — call every 60s from a background thread
    get_stats(ip) — call from detector on every request
    """

    def __init__(self, sliding_window, now_fn=None):
        self._window   = sliding_window
        self._now      = now_fn or time.time

        self._ip_history:    Dict[str, _IPHistory]       = {}
        self._global_history: Dict[int, deque]           = defaultdict(
            lambda: deque(maxlen=HISTORY_SAMPLES)
        )
        self._global_stats:  Dict[int, Optional[Stats]]  = {}

        self._lock         = threading.Lock()
        self._recalc_count = 0

    # ------------------------------------------------------------------
    # Write path — called by background thread
    # ------------------------------------------------------------------

    def recalculate(self, now: Optional[float] = None) -> None:
        """
        Sample current rates from the sliding window, update all baselines.
        ~1ms for <10k IPs. Does not block the request path.
        """
        now  = now if now is not None else self._now()
        hour = _hour_of_day(now)

        snapshot    = self._window.ip_snapshot(as_of=now)
        global_rate = self._window.global_rate(as_of=now)

        with self._lock:
            self._recalc_count += 1

            # Global population baseline (per hour segment)
            self._global_history[hour].append(float(global_rate))
            self._global_stats[hour] = _compute_stats(
                list(self._global_history[hour]), hour=hour, is_cold=False
            )

            # Per-IP baselines
            for ip, rate in snapshot.items():
                if ip not in self._ip_history:
                    self._ip_history[ip] = _IPHistory()

                h = self._ip_history[ip]
                h.samples.append(float(rate))
                h.last_recalc = now

                if len(h.samples) >= MIN_SAMPLES_FOR_IP:
                    h.cached_stats = _compute_stats(
                        list(h.samples), hour=hour, is_cold=False
                    )

        logger.debug(
            "Baseline recalc #%d | hour=%02d | ips=%d | global_rate=%d",
            self._recalc_count, hour, len(snapshot), global_rate,
        )

    # ------------------------------------------------------------------
    # Read path — called by detector on every request
    # ------------------------------------------------------------------

    def get_stats(self, source_ip: str, now: Optional[float] = None) -> Stats:
        """
        Return Stats for source_ip. Never raises.

        Priority:
          1. Per-IP stats (>= MIN_SAMPLES_FOR_IP samples)
          2. Global stats for current hour (cold start)
          3. Safe conservative default (system just started)
        """
        now  = now if now is not None else self._now()
        hour = _hour_of_day(now)

        with self._lock:
            h = self._ip_history.get(source_ip)

            if h is not None and h.cached_stats is not None:
                return h.cached_stats

            global_stats = self._global_stats.get(hour)
            if global_stats is not None:
                return Stats(
                    mean=global_stats.mean,
                    stddev=global_stats.stddev,
                    sample_count=global_stats.sample_count,
                    is_cold=True,
                    hour_segment=hour,
                )

            return _cold_default(hour)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def tracked_ip_count(self) -> int:
        with self._lock:
            return len(self._ip_history)

    def sample_count(self, ip: str) -> int:
        with self._lock:
            h = self._ip_history.get(ip)
            return len(h.samples) if h else 0

    def recalc_count(self) -> int:
        return self._recalc_count


# ---------------------------------------------------------------------------
# Pure calculation functions — no IO, no state, fully testable in isolation
# ---------------------------------------------------------------------------

def _compute_stats(samples: list, hour: int, is_cold: bool) -> Stats:
    """
    Compute mean and stddev from rate samples. Apply floors. Never return
    zero stddev or zero mean.

    Floor rationale:
      Mean floor 2.0  — an IP averaging <2 req/min is too sparse for reliable
                        stats. Raising the floor prevents extreme Z-scores from
                        a single request above a near-zero mean.
      Stddev floor 1.5 — even a perfectly regular IP gets 1.5 req/min of
                        breathing room before being flagged.
    """
    n = len(samples)
    if n == 0:
        return _cold_default(hour)

    mean = sum(samples) / n

    if n > 1:
        variance = sum((x - mean) ** 2 for x in samples) / n
        stddev = math.sqrt(variance)
    else:
        stddev = 0.0

    mean   = max(mean, MEAN_FLOOR)
    stddev = max(stddev, STDDEV_FLOOR)

    return Stats(
        mean=mean,
        stddev=stddev,
        sample_count=n,
        is_cold=is_cold,
        hour_segment=hour,
    )


def _cold_default(hour: int) -> Stats:
    """
    Conservative fallback when no data exists.
    Wide band → less sensitive → fewer false positives at startup.
    An IP only gets flagged during cold start if it is wildly abnormal.
    """
    return Stats(
        mean=MEAN_FLOOR * 5,      # 10.0
        stddev=STDDEV_FLOOR * 4,  # 6.0
        sample_count=0,
        is_cold=True,
        hour_segment=hour,
    )


def _hour_of_day(unix_ts: float) -> int:
    """Extract UTC hour (0-23) from a Unix timestamp."""
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).hour
