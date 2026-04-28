"""
detector/sliding_window.py — Sliding window request rate tracker.

Tracks:
  1. Global request rate  — all traffic across all IPs, last N seconds
  2. Per-IP request rate  — per client, last N seconds

Design decisions:
  - One deque per IP storing float timestamps, newest on right → O(1) append + evict
  - Eviction is TIME-based (not count-based), so maxlen is NOT set on deques
  - All time comparisons use the log entry's own timestamp, not time.time(),
    so replayed/delayed log lines land in the correct window
  - time.time() is only used as the DEFAULT for `as_of` when the caller
    doesn't supply a reference time — making the class fully testable
    without mocking the clock
"""

import time
import threading
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_EMPTY = 0


class SlidingWindow:
    """
    Per-second-granularity request rate tracker.

    All public methods are thread-safe.

    Usage:
        window = SlidingWindow(window_seconds=60)
        window.record(entry.source_ip, entry.timestamp)   # hot path
        window.ip_rate("1.2.3.4")                         # query
        window.global_rate()
        window.ip_snapshot()
    """

    def __init__(
        self,
        window_seconds: int = 60,
        max_ips: int = 50_000,
        evict_interval: int = 300,
    ):
        self.window_seconds = window_seconds
        self.max_ips = max_ips
        self.evict_interval = evict_interval

        self._global: deque[float] = deque()
        self._per_ip: Dict[str, deque] = {}
        self._ip_last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._record_count = 0

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def record(self, source_ip: str, timestamp: datetime) -> None:
        """Record one request. Called by the monitor handler on every log entry."""
        ts = _to_float(timestamp)

        with self._lock:
            # Global window — append then evict using the log timestamp as reference
            self._global.append(ts)
            self._evict_window(self._global, ts)

            # Per-IP window
            if source_ip not in self._per_ip:
                self._ensure_capacity(ts)
                self._per_ip[source_ip] = deque()

            self._per_ip[source_ip].append(ts)
            self._ip_last_seen[source_ip] = ts
            self._evict_window(self._per_ip[source_ip], ts)

            # Periodic sweep of empty IP entries
            self._record_count += 1
            if self._record_count % self.evict_interval == 0:
                self._sweep_empty_ips(ts)

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def global_rate(self, as_of: Optional[float] = None) -> int:
        """Requests across ALL IPs in the last window_seconds."""
        now = as_of if as_of is not None else time.time()
        with self._lock:
            self._evict_window(self._global, now)
            return len(self._global)

    def ip_rate(self, source_ip: str, as_of: Optional[float] = None) -> int:
        """Requests from source_ip in the last window_seconds. Returns 0 if unknown."""
        now = as_of if as_of is not None else time.time()
        with self._lock:
            window = self._per_ip.get(source_ip)
            if window is None:
                return _EMPTY
            self._evict_window(window, now)
            return len(window)

    def ip_snapshot(self, as_of: Optional[float] = None) -> Dict[str, int]:
        """{ip: count} for all IPs with activity in the current window."""
        now = as_of if as_of is not None else time.time()
        result = {}
        with self._lock:
            for ip, window in self._per_ip.items():
                self._evict_window(window, now)
                if len(window) > _EMPTY:
                    result[ip] = len(window)
        return result

    def tracked_ip_count(self) -> int:
        """Number of IPs with at least one entry in their window."""
        with self._lock:
            return sum(1 for w in self._per_ip.values() if len(w) > 0)

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def _evict_window(self, window: deque, now: float) -> None:
        """
        Pop timestamps older than (now - window_seconds) from the left.

        Because entries are appended in chronological order, the left
        side is always the oldest — popleft() until in-window.

        O(k) where k = evicted entries. In steady state k ≈ 0 or 1.
        """
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def _sweep_empty_ips(self, now: float) -> None:
        """
        Remove IP entries whose most recent request is outside the window.
        Called every evict_interval records to prevent unbounded dict growth.
        """
        cutoff = now - self.window_seconds
        dead = [
            ip for ip, window in self._per_ip.items()
            if not window or window[-1] < cutoff
        ]
        for ip in dead:
            del self._per_ip[ip]
            del self._ip_last_seen[ip]
        if dead:
            logger.debug("Swept %d idle IPs.", len(dead))

    def _ensure_capacity(self, now: float) -> None:
        """Evict the least-recently-seen IP when at max_ips cap."""
        if len(self._per_ip) >= self.max_ips:
            oldest = min(self._ip_last_seen, key=self._ip_last_seen.get)
            del self._per_ip[oldest]
            del self._ip_last_seen[oldest]
            logger.warning("max_ips cap reached. Evicted: %s", oldest)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_float(dt: datetime) -> float:
    """
    Convert a datetime to a Unix timestamp float.

    We always use the log entry's timestamp — not the current wall clock —
    so that delayed or replayed log lines land in the correct window position.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()
