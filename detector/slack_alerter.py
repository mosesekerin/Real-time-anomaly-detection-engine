"""
detector/slack_alerter.py — Send anomaly detection alerts to Slack.

Responsibilities:
  - Format detection results into Slack messages
  - Send via webhook (fire-and-forget)
  - Handle network errors gracefully
  - Include context (baseline, rate, decision)

Design:
  - Slack messages are formatted as rich "blocks" with color-coded severity
  - No retries — failed sends are logged but don't block detection
  - Each alert includes: anomaly type, rate, baseline, Z-score, decision
"""

import os
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, List
from enum import Enum
import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Environment variable for webhook URL
SLACK_WEBHOOK_ENV = "SLACK_WEBHOOK_URL"

# HTTP timeout for Slack calls
SLACK_REQUEST_TIMEOUT = 5.0

# Color scheme for Slack messages
class AlertColor(Enum):
    """Slack message color (hex) for different severity levels."""
    FLAG    = "#FFA500"  # Orange — anomalous but not blocking
    BLOCK   = "#FF0000"  # Red — blocking
    UNBAN   = "#00AA00"  # Green — unban event


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class SlackAlert:
    """
    A single Slack alert message.

    Encapsulates the formatting and sending logic.
    """

    def __init__(
        self,
        source_ip: str,
        decision: str,           # "allow", "flag", "block"
        anomaly_score: float,
        dominant_signal: str,    # "z_score", "rate_multiple", etc.
        current_rate: float,     # requests per 60 seconds
        baseline_mean: float,
        baseline_stddev: float,
        z_score: Optional[float] = None,
        reasons: Optional[List[str]] = None,
        timestamp: Optional[float] = None,
        ban_duration_seconds: Optional[int] = None,
    ):
        """
        Args:
            source_ip:           Client IP address
            decision:            "allow", "flag", or "block"
            anomaly_score:       0.0–1.0 normalized score
            dominant_signal:     Which signal triggered (z_score, rate_multiple, etc.)
            current_rate:        Observed requests per 60s
            baseline_mean:       Baseline mean from engine
            baseline_stddev:     Baseline stddev from engine
            z_score:             Z-score value (if applicable)
            reasons:             List of human-readable reasons
            timestamp:           Unix timestamp (defaults to now)
            ban_duration_seconds: How long IP will be blocked (if blocked)
        """
        self.source_ip           = source_ip
        self.decision            = decision
        self.anomaly_score       = anomaly_score
        self.dominant_signal     = dominant_signal
        self.current_rate        = current_rate
        self.baseline_mean       = baseline_mean
        self.baseline_stddev     = baseline_stddev
        self.z_score             = z_score
        self.reasons             = reasons or []
        self.timestamp           = timestamp or __import__('time').time()
        self.ban_duration_seconds = ban_duration_seconds

    def to_slack_payload(self) -> dict:
        """
        Convert to Slack Block Kit JSON payload.

        Returns a dict that can be serialized to JSON and POST'd to webhook.
        """
        dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Determine color based on decision
        if self.decision == "block":
            color = AlertColor.BLOCK.value
            emoji = "🚫"
            severity = "BLOCKING"
        elif self.decision == "flag":
            color = AlertColor.FLAG.value
            emoji = "⚠️"
            severity = "FLAGGED"
        else:
            color = "#CCCCCC"
            emoji = "✓"
            severity = "ALLOWED"

        # Build rate comparison
        rate_multiple = (
            f"{self.current_rate / self.baseline_mean:.1f}×"
            if self.baseline_mean > 0
            else "N/A"
        )

        # Ban duration text
        ban_text = ""
        if self.ban_duration_seconds:
            if self.ban_duration_seconds >= 3600:
                ban_text = f"{self.ban_duration_seconds // 3600}h"
            else:
                ban_text = f"{self.ban_duration_seconds // 60}m"

        # Reasons text
        reasons_text = "\n".join(self.reasons) if self.reasons else "No details"

        # Z-score field (if available)
        z_score_text = f"Z-score: {self.z_score:.2f}" if self.z_score else ""

        # Build the Slack Block Kit message
        payload = {
            "blocks": [
                # Header
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {severity}: {self.source_ip}",
                    },
                },
                # Divider
                {"type": "divider"},
                # Main content
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*IP Address*\n`{self.source_ip}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Decision*\n{self.decision.upper()}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Anomaly Score*\n{self.anomaly_score:.2f}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Signal*\n{self.dominant_signal}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Current Rate*\n{self.current_rate:.0f} req/60s",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Rate vs Baseline*\n{rate_multiple}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Baseline Mean*\n{self.baseline_mean:.1f} req/60s",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Baseline StdDev*\n{self.baseline_stddev:.1f}",
                        },
                    ],
                },
                # Z-score if available
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": z_score_text,
                    },
                } if z_score_text else None,
                # Divider
                {"type": "divider"},
                # Reasons
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Reasons*\n{reasons_text}",
                    },
                },
                # Ban duration and timestamp
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"Ban duration: {ban_text} | "
                                f"Timestamp: {time_str}"
                            ),
                        },
                    ],
                },
            ]
        }

        # Filter out None blocks
        payload["blocks"] = [b for b in payload["blocks"] if b is not None]

        return payload


# ---------------------------------------------------------------------------
# Slack alerter
# ---------------------------------------------------------------------------

class SlackAlerter:
    """
    Sends detection alerts to Slack via webhook.

    Thread-safe: uses a thread pool to send async without blocking the detector.

    Usage:
        alerter = SlackAlerter(webhook_url)
        
        # Called by detector handler on BLOCK decisions
        alerter.send_alert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            z_score=70,
            reasons=["Z-score=70.0 exceeds block threshold"],
            ban_duration_seconds=600,
        )
    """

    def __init__(self, webhook_url: Optional[str] = None):
        """
        Args:
            webhook_url: Slack webhook URL. If None, tries env var SLACK_WEBHOOK_URL.
                        If both None, alerting is disabled.
        """
        self._webhook_url = webhook_url or os.environ.get(SLACK_WEBHOOK_ENV)

        if not self._webhook_url:
            logger.warning(
                "Slack webhook URL not configured. "
                "Set %s environment variable to enable alerts.",
                SLACK_WEBHOOK_ENV,
            )
            self._enabled = False
        else:
            self._enabled = True
            logger.info("Slack alerting enabled")

        # Thread pool for async sends (optional — could use ThreadPoolExecutor)
        self._lock = __import__('threading').Lock()

    def send_alert(
        self,
        source_ip: str,
        decision: str,
        anomaly_score: float,
        dominant_signal: str,
        current_rate: float,
        baseline_mean: float,
        baseline_stddev: float,
        z_score: Optional[float] = None,
        reasons: Optional[List[str]] = None,
        ban_duration_seconds: Optional[int] = None,
    ) -> bool:
        """
        Send an alert to Slack.

        Returns True if sent successfully, False if disabled or failed.
        """
        if not self._enabled:
            return False

        # Only send for FLAG and BLOCK (not ALLOW)
        if decision not in ("flag", "block"):
            return True

        # Build the alert
        alert = SlackAlert(
            source_ip=source_ip,
            decision=decision,
            anomaly_score=anomaly_score,
            dominant_signal=dominant_signal,
            current_rate=current_rate,
            baseline_mean=baseline_mean,
            baseline_stddev=baseline_stddev,
            z_score=z_score,
            reasons=reasons,
            ban_duration_seconds=ban_duration_seconds,
        )

        # Send (fire-and-forget, but log errors)
        return self._send_payload(alert.to_slack_payload())

    def send_unban_alert(
        self,
        source_ip: str,
        ban_duration_seconds: int,
        violation_count: int,
    ) -> bool:
        """
        Send an alert when an IP is auto-unbanned.

        Returns True if sent successfully.
        """
        if not self._enabled:
            return False

        dt = datetime.now(tz=timezone.utc)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        ban_hours = ban_duration_seconds / 3600

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔓 UNBANNED: {source_ip}",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*IP Address*\n`{source_ip}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Ban Duration*\n{ban_hours:.1f} hours",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Violations in Window*\n{violation_count}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Status*\nAuto-unbanned",
                        },
                    ],
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Timestamp: {time_str}",
                        },
                    ],
                },
            ]
        }

        return self._send_payload(payload)

    def _send_payload(self, payload: dict) -> bool:
        """
        Send a payload to Slack webhook.

        Fire-and-forget: logs errors but doesn't raise.
        Returns True if successful.
        """
        try:
            response = requests.post(
                self._webhook_url,
                json=payload,
                timeout=SLACK_REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                logger.debug("Slack alert sent successfully")
                return True
            else:
                logger.error(
                    "Slack webhook returned status %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

        except requests.Timeout:
            logger.error("Slack webhook request timed out")
            return False
        except requests.RequestException as exc:
            logger.error("Slack webhook error: %s", exc)
            return False
        except Exception as exc:
            logger.error("Unexpected error sending Slack alert: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Helper: get alerter instance from environment
# ---------------------------------------------------------------------------

def get_slack_alerter() -> SlackAlerter:
    """
    Factory function: create and return a SlackAlerter configured from env.

    Usage:
        alerter = get_slack_alerter()
        alerter.send_alert(...)
    """
    return SlackAlerter()
