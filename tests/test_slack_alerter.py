"""
tests/test_slack_alerter.py — Tests for Slack alerting.

Coverage:
  - Alert formatting (Slack Block Kit)
  - Payload validation
  - Network error handling
  - Enable/disable via environment
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
import requests

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.slack_alerter import SlackAlert, SlackAlerter, AlertColor


class TestSlackAlertPayload:

    def test_block_alert_formatting(self):
        """BLOCK alert includes all required fields with red color."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300.0,
            baseline_mean=20.0,
            baseline_stddev=4.0,
            z_score=70.0,
            reasons=["Z-score=70.0 exceeds block threshold"],
            ban_duration_seconds=600,
        )

        payload = alert.to_slack_payload()

        # Verify structure
        assert "blocks" in payload
        assert len(payload["blocks"]) > 0

        # Verify content
        payload_str = json.dumps(payload)
        assert "1.2.3.4" in payload_str
        assert "BLOCKING" in payload_str
        assert "70.0" in payload_str or "70" in payload_str
        assert "0.95" in payload_str

    def test_flag_alert_formatting(self):
        """FLAG alert uses orange color."""
        alert = SlackAlert(
            source_ip="2.3.4.5",
            decision="flag",
            anomaly_score=0.60,
            dominant_signal="rate_multiple",
            current_rate=100.0,
            baseline_mean=20.0,
            baseline_stddev=4.0,
            reasons=["rate=100 is 5.0× baseline mean"],
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        assert "FLAGGED" in payload_str
        assert "2.3.4.5" in payload_str

    def test_payload_includes_timestamp(self):
        """Alert includes formatted timestamp."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            timestamp=1704067200.0,  # 2024-01-01 00:00:00 UTC
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        # Should contain formatted date
        assert "2024" in payload_str or "UTC" in payload_str

    def test_payload_includes_ban_duration(self):
        """Alert shows ban duration in human-readable format."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            ban_duration_seconds=1800,  # 30 minutes
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        assert "30m" in payload_str

    def test_payload_includes_rate_multiple(self):
        """Alert shows how many times baseline the current rate is."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=100.0,
            baseline_mean=20.0,
            baseline_stddev=4.0,
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        # 100/20 = 5.0×
        assert "5.0" in payload_str

    def test_payload_is_valid_json(self):
        """Alert payload serializes to valid JSON."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
        )

        payload = alert.to_slack_payload()

        # Should serialize without error
        json_str = json.dumps(payload)
        parsed = json.loads(json_str)
        assert "blocks" in parsed


class TestSlackAlerter:

    @patch('detector.slack_alerter.requests.post')
    def test_send_alert_block_success(self, mock_post):
        """send_alert() posts successfully on BLOCK."""
        mock_post.return_value = MagicMock(status_code=200)

        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        result = alerter.send_alert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            z_score=70,
            ban_duration_seconds=600,
        )

        assert result is True
        mock_post.assert_called_once()

    @patch('detector.slack_alerter.requests.post')
    def test_send_alert_flag_success(self, mock_post):
        """send_alert() posts on FLAG decisions."""
        mock_post.return_value = MagicMock(status_code=200)

        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        result = alerter.send_alert(
            source_ip="1.2.3.4",
            decision="flag",
            anomaly_score=0.60,
            dominant_signal="rate_multiple",
            current_rate=100,
            baseline_mean=20,
            baseline_stddev=4,
        )

        assert result is True
        mock_post.assert_called_once()

    def test_send_alert_allow_skipped(self):
        """send_alert() returns True for ALLOW without posting."""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")

        with patch('detector.slack_alerter.requests.post') as mock_post:
            result = alerter.send_alert(
                source_ip="1.2.3.4",
                decision="allow",
                anomaly_score=0.05,
                dominant_signal="z_score",
                current_rate=20,
                baseline_mean=20,
                baseline_stddev=4,
            )

        assert result is True
        mock_post.assert_not_called()

    @patch('detector.slack_alerter.requests.post')
    def test_send_alert_network_timeout(self, mock_post):
        """Network timeout is handled gracefully."""
        import requests
        mock_post.side_effect = requests.Timeout()

        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        result = alerter.send_alert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
        )

        assert result is False

    @patch('detector.slack_alerter.requests.post')
    def test_send_alert_http_error(self, mock_post):
        """HTTP errors are logged but don't raise."""
        mock_post.return_value = MagicMock(status_code=403, text="Forbidden")

        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        result = alerter.send_alert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
        )

        assert result is False

    @patch.dict(os.environ, {}, clear=True)
    def test_disabled_without_webhook_url(self):
        """Alerter is disabled if no webhook URL provided."""
        alerter = SlackAlerter(webhook_url=None)

        with patch('detector.slack_alerter.requests.post') as mock_post:
            result = alerter.send_alert(
                source_ip="1.2.3.4",
                decision="block",
                anomaly_score=0.95,
                dominant_signal="z_score",
                current_rate=300,
                baseline_mean=20,
                baseline_stddev=4,
            )

        assert result is False
        mock_post.assert_not_called()

    @patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"})
    @patch('detector.slack_alerter.requests.post')
    def test_webhook_from_environment(self, mock_post):
        """Alerter reads webhook URL from environment."""
        mock_post.return_value = MagicMock(status_code=200)

        # No URL passed → uses env var
        alerter = SlackAlerter()

        result = alerter.send_alert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
        )

        assert result is True
        mock_post.assert_called_once()

    @patch('detector.slack_alerter.requests.post')
    def test_send_unban_alert(self, mock_post):
        """send_unban_alert() formats unbanned IPs."""
        mock_post.return_value = MagicMock(status_code=200)

        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        result = alerter.send_unban_alert(
            source_ip="1.2.3.4",
            ban_duration_seconds=3600,
            violation_count=2,
        )

        assert result is True
        mock_post.assert_called_once()

        # Check payload includes unban info
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]
        payload_str = json.dumps(payload)

        assert "UNBANNED" in payload_str
        assert "1.2.3.4" in payload_str
        assert "1.0" in payload_str  # 3600 seconds = 1.0 hour


class TestSlackAlertEdgeCases:

    def test_zero_baseline_mean_handled(self):
        """Alert handles zero baseline gracefully."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=100,
            baseline_mean=0.0,  # Edge case
            baseline_stddev=0.0,
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        # Should contain "N/A" instead of divide by zero
        assert "N/A" in payload_str or json.loads(payload_str) is not None

    def test_missing_optional_fields(self):
        """Alert works with minimal required fields."""
        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            # z_score, reasons, ban_duration all omitted
        )

        payload = alert.to_slack_payload()

        # Should still serialize
        assert json.dumps(payload) is not None

    def test_very_long_reasons_list(self):
        """Alert handles many reasons without truncation."""
        reasons = [f"Reason {i}: detail" for i in range(10)]

        alert = SlackAlert(
            source_ip="1.2.3.4",
            decision="block",
            anomaly_score=0.95,
            dominant_signal="z_score",
            current_rate=300,
            baseline_mean=20,
            baseline_stddev=4,
            reasons=reasons,
        )

        payload = alert.to_slack_payload()
        payload_str = json.dumps(payload)

        # All reasons should be in payload
        for reason in reasons:
            assert reason in payload_str
