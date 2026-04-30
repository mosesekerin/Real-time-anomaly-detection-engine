"""
detector/metrics_writer.py — Write detector state for dashboard consumption.

The detector periodically calls write_metrics() to share:
  - Global request rate
  - Top attacking IPs (by rate)
  - Baseline statistics
  
This allows the dashboard to read from JSON files instead of 
introspecting detector internals.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Output files
METRICS_FILE = "/tmp/hng_metrics.json"
ALERTS_LOG_FILE = "/tmp/hng_alerts.jsonl"


class MetricsWriter:
    """Writes detector metrics to shared JSON files."""

    @staticmethod
    def write_metrics(
        global_rate: float,
        top_ips: List[Dict],
        baseline_mean: float,
        baseline_stddev: float,
        now: Optional[float] = None,
    ) -> bool:
        """
        Write metrics to dashboard.

        Args:
            global_rate: Requests per second (global)
            top_ips: List of dicts: [{"ip": "1.2.3.4", "rate": 100}, ...]
            baseline_mean: Global baseline mean
            baseline_stddev: Global baseline stddev
            now: Timestamp (defaults to time.time())

        Returns:
            True if successful, False otherwise.
        """
        now = now if now is not None else time.time()

        payload = {
            "timestamp": now,
            "datetime": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "global_rate": global_rate,
            "top_ips": top_ips,
            "baseline_mean": baseline_mean,
            "baseline_stddev": baseline_stddev,
        }

        try:
            with open(METRICS_FILE, "w") as f:
                json.dump(payload, f)
            return True
        except Exception as exc:
            logger.error("Failed to write metrics: %s", exc)
            return False

    @staticmethod
    def log_alert(
        source_ip: str,
        decision: str,  # "block", "flag", "unban"
        score: float,
        reason: str,
        now: Optional[float] = None,
    ) -> bool:
        """
        Append an alert event to the alerts log (JSONL format).

        Each line is a complete JSON object with one alert.

        Args:
            source_ip: The IP that triggered the alert
            decision: "block", "flag", or "unban"
            score: Anomaly score (0.0–1.0)
            reason: Human-readable reason
            now: Timestamp (defaults to time.time())

        Returns:
            True if successful, False otherwise.
        """
        now = now if now is not None else time.time()

        alert = {
            "timestamp": now,
            "source_ip": source_ip,
            "decision": decision,
            "score": score,
            "reason": reason,
        }

        try:
            with open(ALERTS_LOG_FILE, "a") as f:
                f.write(json.dumps(alert) + "\n")
            return True
        except Exception as exc:
            logger.error("Failed to log alert: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Usage example (for integration into detector main loop)
# ---------------------------------------------------------------------------

def example_usage():
    """
    Example: how to use MetricsWriter in the detector main loop.

    Called once per second from the detector loop.
    """
    from detector.sliding_window import SlidingWindow
    from detector.baseline import BaselineEngine

    # Assume these exist
    window = SlidingWindow()
    baseline = BaselineEngine(window)

    # Every second (or configurable interval):
    now = time.time()
    global_rate = window.global_rate(as_of=now)
    
    # Top 10 IPs by rate
    snapshot = window.ip_snapshot(as_of=now)
    top_ips = sorted(
        [{"ip": ip, "rate": rate} for ip, rate in snapshot.items()],
        key=lambda x: x["rate"],
        reverse=True,
    )[:10]

    # Global baseline
    global_stats = baseline.get_stats("__global__", now=now)

    # Write metrics for dashboard
    MetricsWriter.write_metrics(
        global_rate=global_rate,
        top_ips=top_ips,
        baseline_mean=global_stats.mean,
        baseline_stddev=global_stats.stddev,
        now=now,
    )

    # When blocking an IP:
    MetricsWriter.log_alert(
        source_ip="1.2.3.4",
        decision="block",
        score=0.95,
        reason="Z-score=70.0 exceeds threshold",
        now=now,
    )

    # When unbanning:
    MetricsWriter.log_alert(
        source_ip="1.2.3.4",
        decision="unban",
        score=0.0,
        reason="Auto-unban after 10 minutes",
        now=now,
    )
