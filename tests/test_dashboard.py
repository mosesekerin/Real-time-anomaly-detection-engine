"""
tests/test_dashboard.py — Tests for dashboard and metrics writer.

Coverage:
  - Metrics writer file I/O
  - Dashboard API endpoints
  - HTML rendering
  - Alert log parsing
"""

import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.dashboard import create_app, MetricsReader
from detector.metrics_writer import MetricsWriter


class TestMetricsWriter:

    def test_write_metrics_creates_file(self):
        """write_metrics() creates JSON file with correct structure."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            metrics_file = f.name

        try:
            with patch('detector.metrics_writer.METRICS_FILE', metrics_file):
                result = MetricsWriter.write_metrics(
                    global_rate=150.5,
                    top_ips=[
                        {"ip": "1.2.3.4", "rate": 300},
                        {"ip": "2.3.4.5", "rate": 200},
                    ],
                    baseline_mean=20.0,
                    baseline_stddev=4.0,
                )

            assert result is True
            assert os.path.exists(metrics_file)

            # Read and verify
            with open(metrics_file, 'r') as f:
                data = json.load(f)

            assert data["global_rate"] == 150.5
            assert data["baseline_mean"] == 20.0
            assert len(data["top_ips"]) == 2
            assert data["top_ips"][0]["ip"] == "1.2.3.4"

        finally:
            try:
                os.unlink(metrics_file)
            except FileNotFoundError:
                pass

    def test_write_metrics_includes_timestamp(self):
        """Metrics include timestamp and ISO datetime."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            metrics_file = f.name

        try:
            with patch('detector.metrics_writer.METRICS_FILE', metrics_file):
                now = 1700000000.0
                MetricsWriter.write_metrics(
                    global_rate=100.0,
                    top_ips=[],
                    baseline_mean=20.0,
                    baseline_stddev=4.0,
                    now=now,
                )

            with open(metrics_file, 'r') as f:
                data = json.load(f)

            assert data["timestamp"] == now
            assert "datetime" in data
            assert "2023" in data["datetime"]  # Sanity check

        finally:
            try:
                os.unlink(metrics_file)
            except FileNotFoundError:
                pass

    def test_log_alert_appends_jsonl(self):
        """log_alert() appends to JSONL file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            alerts_file = f.name

        try:
            with patch('detector.metrics_writer.ALERTS_LOG_FILE', alerts_file):
                # Write two alerts
                MetricsWriter.log_alert(
                    source_ip="1.2.3.4",
                    decision="block",
                    score=0.95,
                    reason="Z-score exceeded",
                    now=1700000000.0,
                )
                MetricsWriter.log_alert(
                    source_ip="2.3.4.5",
                    decision="flag",
                    score=0.60,
                    reason="Rate elevated",
                    now=1700000060.0,
                )

            # Read and verify
            with open(alerts_file, 'r') as f:
                lines = f.readlines()

            assert len(lines) == 2

            alert1 = json.loads(lines[0])
            assert alert1["source_ip"] == "1.2.3.4"
            assert alert1["decision"] == "block"

            alert2 = json.loads(lines[1])
            assert alert2["source_ip"] == "2.3.4.5"
            assert alert2["decision"] == "flag"

        finally:
            try:
                os.unlink(alerts_file)
            except FileNotFoundError:
                pass

    def test_write_metrics_error_handling(self):
        """write_metrics() returns False on I/O error."""
        with patch('detector.metrics_writer.METRICS_FILE', '/nonexistent/path/metrics.json'):
            result = MetricsWriter.write_metrics(
                global_rate=100.0,
                top_ips=[],
                baseline_mean=20.0,
                baseline_stddev=4.0,
            )

        assert result is False


class TestMetricsReader:

    def test_read_detector_metrics(self, tmp_path):
        """MetricsReader reads detector metrics file."""
        metrics_file = tmp_path / "metrics.json"
        metrics_file.write_text(json.dumps({
            "global_rate": 150.5,
            "top_ips": [
                {"ip": "1.2.3.4", "rate": 300},
            ],
            "baseline_mean": 20.0,
            "baseline_stddev": 4.0,
        }))

        with patch('detector.dashboard.METRICS_FILE', str(metrics_file)):
            reader = MetricsReader()
            rate, top_ips, mean, stddev = reader._read_detector_metrics()

        assert rate == 150.5
        assert len(top_ips) == 1
        assert top_ips[0]["ip"] == "1.2.3.4"
        assert mean == 20.0
        assert stddev == 4.0

    def test_read_blocklist(self, tmp_path):
        """MetricsReader counts active vs total blocks."""
        blocklist_file = tmp_path / "blocklist.json"
        now = 1700000000.0
        blocklist_file.write_text(json.dumps({
            "1.2.3.4": {
                "blocked_at": now - 100,  # Expired (100s ago, TTL=60)
                "ttl_seconds": 60,
            },
            "2.3.4.5": {
                "blocked_at": now,  # Active (just blocked, TTL=600)
                "ttl_seconds": 600,
            },
        }))

        with patch('detector.dashboard.BLOCKLIST_FILE', str(blocklist_file)):
            reader = MetricsReader()
            with patch('time.time', return_value=now):
                active, total = reader._read_blocklist()

        assert total == 2
        assert active == 1  # Only 2.3.4.5 is still active

    def test_read_recent_alerts(self, tmp_path):
        """MetricsReader reads recent alerts from JSONL."""
        alerts_file = tmp_path / "alerts.jsonl"
        alerts_file.write_text(
            json.dumps({"source_ip": "1.2.3.4", "decision": "block"}) + "\n" +
            json.dumps({"source_ip": "2.3.4.5", "decision": "flag"}) + "\n"
        )

        with patch('detector.dashboard.ALERTS_LOG_FILE', str(alerts_file)):
            reader = MetricsReader()
            alerts = reader.read_recent_alerts(limit=10)

        assert len(alerts) == 2
        assert alerts[0]["source_ip"] == "2.3.4.5"  # Reversed (newest first)
        assert alerts[1]["source_ip"] == "1.2.3.4"


class TestDashboardAPI:

    @pytest.fixture
    def client(self, tmp_path):
        """Create a Flask test client with temp files."""
        with patch('detector.dashboard.METRICS_FILE', str(tmp_path / "metrics.json")):
            with patch('detector.dashboard.BLOCKLIST_FILE', str(tmp_path / "blocklist.json")):
                with patch('detector.dashboard.ALERTS_LOG_FILE', str(tmp_path / "alerts.jsonl")):
                    app = create_app()
                    app.config['TESTING'] = True
                    yield app.test_client()

    def test_dashboard_html_loads(self, client):
        """GET / returns HTML."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'HNG Anomaly Detector' in response.data
        assert b'<html' in response.data

    def test_api_metrics_empty(self, client, tmp_path):
        """GET /api/metrics returns default values when no data."""
        response = client.get('/api/metrics')
        assert response.status_code == 200

        data = response.get_json()
        assert data["global_rate"] == 0.0
        assert data["top_ips"] == []
        assert data["active_blocks"] == 0

    def test_api_metrics_with_data(self, client, tmp_path):
        """GET /api/metrics returns data from metrics file."""
        metrics_file = tmp_path / "metrics.json"
        metrics_file.write_text(json.dumps({
            "global_rate": 150.5,
            "top_ips": [
                {"ip": "1.2.3.4", "rate": 300},
                {"ip": "2.3.4.5", "rate": 200},
            ],
            "baseline_mean": 20.0,
            "baseline_stddev": 4.0,
        }))

        with patch('detector.dashboard.METRICS_FILE', str(metrics_file)):
            response = client.get('/api/metrics')

        data = response.get_json()
        assert data["global_rate"] == 150.5
        assert len(data["top_ips"]) == 2
        assert data["baseline_mean"] == 20.0

    def test_api_alerts_empty(self, client):
        """GET /api/alerts returns empty list when no alerts."""
        response = client.get('/api/alerts')
        assert response.status_code == 200

        data = response.get_json()
        assert data["alerts"] == []

    def test_api_alerts_with_data(self, client, tmp_path):
        """GET /api/alerts returns recent alerts."""
        alerts_file = tmp_path / "alerts.jsonl"
        alerts_file.write_text(
            json.dumps({"source_ip": "1.2.3.4", "decision": "block"}) + "\n"
        )

        with patch('detector.dashboard.ALERTS_LOG_FILE', str(alerts_file)):
            response = client.get('/api/alerts')

        data = response.get_json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["source_ip"] == "1.2.3.4"


class TestDashboardHTML:

    def test_html_contains_key_elements(self, tmp_path):
        """Dashboard HTML includes all required elements."""
        with patch('detector.dashboard.METRICS_FILE', str(tmp_path / "metrics.json")):
            app = create_app()
            client = app.test_client()
            response = client.get('/')

        html = response.data.decode('utf-8')

        # Check for key UI elements
        assert 'global-rate' in html
        assert 'active-blocks' in html
        assert 'cpu-percent' in html
        assert 'memory-percent' in html
        assert 'baseline-mean' in html
        assert 'top-ips-table' in html
        assert 'alerts-list' in html

    def test_html_includes_refresh_script(self, tmp_path):
        """Dashboard HTML includes auto-refresh JavaScript."""
        with patch('detector.dashboard.METRICS_FILE', str(tmp_path / "metrics.json")):
            app = create_app()
            client = app.test_client()
            response = client.get('/')

        html = response.data.decode('utf-8')

        # Check for refresh logic
        assert 'REFRESH_INTERVAL' in html
        assert 'fetch(\'/api/metrics\')' in html
        assert 'setInterval' in html


class TestDashboardEdgeCases:

    def test_metrics_reader_handles_missing_files(self):
        """MetricsReader gracefully handles missing state files."""
        with patch('detector.dashboard.METRICS_FILE', '/nonexistent/metrics.json'):
            with patch('detector.dashboard.BLOCKLIST_FILE', '/nonexistent/blocklist.json'):
                reader = MetricsReader()
                metrics = reader.read_metrics()

        # Should return defaults, not crash
        assert metrics.global_rate == 0.0
        assert metrics.active_blocks == 0
        assert metrics.cpu_percent >= 0

    def test_metrics_reader_handles_corrupted_json(self, tmp_path):
        """MetricsReader handles corrupted JSON gracefully."""
        metrics_file = tmp_path / "metrics.json"
        metrics_file.write_text("{ invalid json")

        with patch('detector.dashboard.METRICS_FILE', str(metrics_file)):
            reader = MetricsReader()
            rate, top_ips, mean, stddev = reader._read_detector_metrics()

        # Should return defaults
        assert rate == 0.0
        assert top_ips == []

    def test_alert_log_with_invalid_lines(self, tmp_path):
        """MetricsReader skips invalid JSON lines in alerts log."""
        alerts_file = tmp_path / "alerts.jsonl"
        alerts_file.write_text(
            json.dumps({"source_ip": "1.2.3.4"}) + "\n" +
            "not valid json\n" +
            json.dumps({"source_ip": "2.3.4.5"}) + "\n"
        )

        with patch('detector.dashboard.ALERTS_LOG_FILE', str(alerts_file)):
            reader = MetricsReader()
            alerts = reader.read_recent_alerts(limit=10)

        # Should skip the invalid line and return 2 alerts
        assert len(alerts) == 2
