"""
main.py — Entrypoint. Wires the monitor with concrete handlers.

Run:
    python -m detector.main

Or inside Docker:
    CMD ["python", "-m", "detector.main"]
"""

import logging
import os
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock

from .monitor import NginxLogMonitor
from .parser import LogEntry

# ---------------------------------------------------------------------------
# Logging setup — structured, no color, safe for Docker log drivers
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)

logger = logging.getLogger("detector.main")


# ---------------------------------------------------------------------------
# Example handler 1: status code distribution tracker
# ---------------------------------------------------------------------------

class StatusDistribution:
    """
    Tracks how many responses fall into each HTTP status class.
    Thread-safe; can be queried from a metrics endpoint.
    """

    def __init__(self):
        self._counts = defaultdict(int)
        self._lock = Lock()

    def __call__(self, entry: LogEntry) -> None:
        bucket = f"{entry.status // 100}xx"
        with self._lock:
            self._counts[bucket] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._counts)


# ---------------------------------------------------------------------------
# Example handler 2: per-IP request rate tracker
# ---------------------------------------------------------------------------

class IPRequestTracker:
    """
    Tracks the last N timestamps per IP.
    Used downstream by the anomaly detector to compute request rates.
    """

    WINDOW_SIZE = 200  # keep last 200 timestamps per IP

    def __init__(self):
        self._windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.WINDOW_SIZE)
        )
        self._lock = Lock()

    def __call__(self, entry: LogEntry) -> None:
        with self._lock:
            self._windows[entry.source_ip].append(entry.timestamp)

    def recent_count(self, ip: str, since: datetime) -> int:
        """How many requests has this IP made since `since`?"""
        with self._lock:
            window = self._windows.get(ip, deque())
            return sum(1 for ts in window if ts >= since)

    def all_ips(self) -> list[str]:
        with self._lock:
            return list(self._windows.keys())


# ---------------------------------------------------------------------------
# Example handler 3: 4xx/5xx error logger
# ---------------------------------------------------------------------------

def log_errors(entry: LogEntry) -> None:
    """Write client and server errors to the application logger."""
    if entry.status >= 400:
        level = logging.WARNING if entry.status < 500 else logging.ERROR
        logger.log(
            level,
            "HTTP %d | ip=%-16s method=%-6s path=%s size=%d",
            entry.status,
            entry.source_ip,
            entry.method,
            entry.path,
            entry.response_size,
        )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    log_path = os.environ.get(
        "NGINX_LOG_PATH",
        "/var/log/nginx/hng-access.log",
    )
    dead_letter_path = os.environ.get(
        "DEAD_LETTER_PATH",
        "/var/log/nginx/hng-access.dead.log",
    )

    logger.info("Starting log monitor. log_path=%s", log_path)

    # Instantiate handlers
    status_dist = StatusDistribution()
    ip_tracker = IPRequestTracker()

    # Build and configure monitor
    monitor = NginxLogMonitor(
        log_path=log_path,
        dead_letter_path=dead_letter_path,
        metrics_interval=60.0,
    )
    monitor.add_handler(status_dist)
    monitor.add_handler(ip_tracker)
    monitor.add_handler(log_errors)

    # Blocking call — returns only on stop() or fatal tailer error
    monitor.run()

    # Final status snapshot on exit
    logger.info("Final status distribution: %s", status_dist.snapshot())


if __name__ == "__main__":
    main()
