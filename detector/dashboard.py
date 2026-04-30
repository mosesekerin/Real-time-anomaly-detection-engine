"""
detector/dashboard.py — Real-time anomaly detection dashboard.

HTTP server that displays:
  - Global request rate (req/sec)
  - Top attacking IPs
  - Currently banned IPs with TTLs
  - Baseline statistics (mean, stddev)
  - System resource usage (CPU, memory)
  - Uptime
  - Real-time alerts log

Reads from detector's shared state files:
  - /tmp/hng_metrics.json (written by detector every second)
  - /tmp/hng_blocklist.json (written by blocker)
  - /tmp/hng_violation_history.json (written by unbanner)
  - /tmp/hng_alerts.jsonl (written by detector on block/flag)

Design: Flask HTTP server with WebSocket-style polling via JS
Auto-refresh every 3 seconds using fetch() + DOM update
"""

import os
import json
import time
import psutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

from flask import Flask, render_template_string, jsonify

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

METRICS_FILE = "/tmp/hng_metrics.json"
BLOCKLIST_FILE = "/tmp/hng_blocklist.json"
VIOLATION_HISTORY_FILE = "/tmp/hng_violation_history.json"
ALERTS_LOG_FILE = "/tmp/hng_alerts.jsonl"

DASHBOARD_PORT = 8080
DASHBOARD_HOST = "0.0.0.0"
REFRESH_INTERVAL_SECONDS = 3


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SystemMetrics:
    """Current system and detector metrics."""
    global_rate: float          # requests per second
    top_ips: List[Dict]         # [{"ip": "1.2.3.4", "rate": 100}, ...]
    active_blocks: int          # number of currently blocked IPs
    total_blocks: int           # total IPs ever blocked
    baseline_mean: float        # global baseline mean
    baseline_stddev: float      # global baseline stddev
    cpu_percent: float          # CPU usage %
    memory_percent: float       # Memory usage %
    uptime_seconds: float       # how long detector has been running
    timestamp: float            # when metrics were sampled


# ---------------------------------------------------------------------------
# Metrics reader
# ---------------------------------------------------------------------------

class MetricsReader:
    """Reads detector state from shared JSON files."""

    def __init__(self):
        self._start_time = time.time()

    def read_metrics(self) -> SystemMetrics:
        """Read all available metrics and return a SystemMetrics object."""
        # Global rate and baseline
        global_rate, top_ips, baseline_mean, baseline_stddev = self._read_detector_metrics()

        # Blocked IPs
        active_blocks, total_blocks = self._read_blocklist()

        # System info
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        uptime = time.time() - self._start_time

        return SystemMetrics(
            global_rate=global_rate,
            top_ips=top_ips,
            active_blocks=active_blocks,
            total_blocks=total_blocks,
            baseline_mean=baseline_mean,
            baseline_stddev=baseline_stddev,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            uptime_seconds=uptime,
            timestamp=time.time(),
        )

    def read_recent_alerts(self, limit: int = 20) -> List[Dict]:
        """Read the most recent alert events from the alerts log."""
        alerts = []

        if not os.path.exists(ALERTS_LOG_FILE):
            return alerts

        try:
            with open(ALERTS_LOG_FILE, "r") as f:
                lines = f.readlines()

            # Read last `limit` lines
            for line in lines[-limit:]:
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    pass

            # Reverse so newest is first
            alerts.reverse()

        except Exception as exc:
            logger.error("Failed to read alerts: %s", exc)

        return alerts

    # ------------------------------------------------------------------
    # Private: file readers
    # ------------------------------------------------------------------

    def _read_detector_metrics(self) -> tuple:
        """
        Read global rate, top IPs, and baseline from detector metrics file.
        Returns: (global_rate, top_ips, baseline_mean, baseline_stddev)
        """
        global_rate = 0.0
        top_ips = []
        baseline_mean = 0.0
        baseline_stddev = 0.0

        if not os.path.exists(METRICS_FILE):
            return global_rate, top_ips, baseline_mean, baseline_stddev

        try:
            with open(METRICS_FILE, "r") as f:
                data = json.load(f)

            global_rate = data.get("global_rate", 0.0)
            top_ips = data.get("top_ips", [])
            baseline_mean = data.get("baseline_mean", 0.0)
            baseline_stddev = data.get("baseline_stddev", 0.0)

        except Exception as exc:
            logger.error("Failed to read metrics: %s", exc)

        return global_rate, top_ips, baseline_mean, baseline_stddev

    def _read_blocklist(self) -> tuple:
        """
        Read blocklist and return (active_blocks, total_blocks).
        Active = not expired. Total = all entries.
        """
        active_blocks = 0
        total_blocks = 0

        if not os.path.exists(BLOCKLIST_FILE):
            return active_blocks, total_blocks

        try:
            with open(BLOCKLIST_FILE, "r") as f:
                data = json.load(f)

            now = time.time()
            for ip, record in data.items():
                total_blocks += 1
                expires_at = record.get("blocked_at", 0) + record.get("ttl_seconds", 0)
                if now < expires_at:
                    active_blocks += 1

        except Exception as exc:
            logger.error("Failed to read blocklist: %s", exc)

        return active_blocks, total_blocks


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    metrics_reader = MetricsReader()

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def dashboard():
        """Main dashboard page (HTML)."""
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/metrics")
    def api_metrics():
        """API endpoint: return current metrics as JSON."""
        metrics = metrics_reader.read_metrics()

        return jsonify({
            "global_rate": round(metrics.global_rate, 2),
            "top_ips": metrics.top_ips[:10],  # Top 10
            "active_blocks": metrics.active_blocks,
            "total_blocks": metrics.total_blocks,
            "baseline_mean": round(metrics.baseline_mean, 2),
            "baseline_stddev": round(metrics.baseline_stddev, 2),
            "cpu_percent": round(metrics.cpu_percent, 1),
            "memory_percent": round(metrics.memory_percent, 1),
            "uptime_seconds": round(metrics.uptime_seconds),
            "timestamp": metrics.timestamp,
        })

    @app.route("/api/alerts")
    def api_alerts():
        """API endpoint: return recent alerts."""
        alerts = metrics_reader.read_recent_alerts(limit=20)
        return jsonify({"alerts": alerts})

    return app


# ---------------------------------------------------------------------------
# HTML template (embedded in Python)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detector — Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #0f0f1e 0%, #1a1a2e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #16a34a;
        }

        h1 {
            font-size: 2em;
            font-weight: 700;
            letter-spacing: -0.5px;
        }

        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            background: #16a34a;
            color: white;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }

        .status-badge.warning {
            background: #ea580c;
        }

        .status-badge.critical {
            background: #dc2626;
        }

        .refresh-info {
            font-size: 0.85em;
            color: #999;
        }

        /* Grid layout */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: rgba(30, 30, 40, 0.8);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }

        .card:hover {
            border-color: #16a34a;
            box-shadow: 0 0 20px rgba(22, 163, 74, 0.2);
        }

        .card-title {
            font-size: 0.9em;
            font-weight: 600;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
        }

        .card-value {
            font-size: 2.5em;
            font-weight: 700;
            color: #16a34a;
            font-family: "Courier New", monospace;
        }

        .card-subtitle {
            font-size: 0.85em;
            color: #666;
            margin-top: 8px;
        }

        .card.warning .card-value {
            color: #ea580c;
        }

        .card.critical .card-value {
            color: #dc2626;
        }

        /* Two-column for wide cards */
        @media (min-width: 1024px) {
            .grid-2col {
                grid-column: span 2;
            }
        }

        /* Table */
        .table-container {
            background: rgba(30, 30, 40, 0.8);
            border: 1px solid #333;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }

        .table-header {
            padding: 20px;
            border-bottom: 1px solid #333;
        }

        .table-header h2 {
            font-size: 1.2em;
            margin: 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: rgba(0, 0, 0, 0.3);
            padding: 12px 20px;
            text-align: left;
            font-size: 0.85em;
            font-weight: 600;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #333;
        }

        td {
            padding: 12px 20px;
            border-bottom: 1px solid #222;
            font-size: 0.9em;
        }

        tr:hover {
            background: rgba(22, 163, 74, 0.05);
        }

        tr:last-child td {
            border-bottom: none;
        }

        .ip-addr {
            font-family: "Courier New", monospace;
            font-weight: 600;
            color: #16a34a;
        }

        .rate-high {
            color: #dc2626;
            font-weight: 600;
        }

        .rate-medium {
            color: #ea580c;
            font-weight: 600;
        }

        .rate-low {
            color: #16a34a;
        }

        /* Alerts log */
        .alert-log {
            background: rgba(30, 30, 40, 0.8);
            border: 1px solid #333;
            border-radius: 8px;
            overflow: hidden;
        }

        .alert-log-header {
            padding: 20px;
            border-bottom: 1px solid #333;
        }

        .alert-log-header h2 {
            margin: 0;
            font-size: 1.2em;
        }

        .alert-entry {
            padding: 12px 20px;
            border-bottom: 1px solid #222;
            font-size: 0.85em;
            font-family: "Courier New", monospace;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .alert-entry:last-child {
            border-bottom: none;
        }

        .alert-entry.block {
            background: rgba(220, 38, 38, 0.05);
            border-left: 3px solid #dc2626;
        }

        .alert-entry.flag {
            background: rgba(234, 88, 12, 0.05);
            border-left: 3px solid #ea580c;
        }

        .alert-entry.unban {
            background: rgba(22, 163, 74, 0.05);
            border-left: 3px solid #16a34a;
        }

        .alert-ip {
            color: #16a34a;
            font-weight: 600;
            min-width: 120px;
        }

        .alert-decision {
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: 600;
        }

        .alert-decision.block {
            background: #dc2626;
            color: white;
        }

        .alert-decision.flag {
            background: #ea580c;
            color: white;
        }

        .alert-decision.unban {
            background: #16a34a;
            color: white;
        }

        .alert-time {
            color: #666;
            min-width: 150px;
            text-align: right;
        }

        /* Empty state */
        .empty {
            text-align: center;
            padding: 40px;
            color: #666;
        }

        .empty p {
            margin: 0;
        }

        /* Footer */
        footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.85em;
        }

        .last-update {
            color: #666;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div>
                <h1>🛡️ HNG Anomaly Detector</h1>
                <p class="refresh-info">Auto-refresh every 3 seconds</p>
            </div>
            <div>
                <span id="status-badge" class="status-badge">● ONLINE</span>
                <p class="last-update">Updated: <span id="last-update">—</span></p>
            </div>
        </header>

        <!-- KPI Cards -->
        <div class="grid">
            <div class="card">
                <div class="card-title">Global Rate</div>
                <div class="card-value" id="global-rate">0</div>
                <div class="card-subtitle">requests/sec</div>
            </div>

            <div class="card">
                <div class="card-title">Blocked IPs</div>
                <div class="card-value" id="active-blocks">0</div>
                <div class="card-subtitle"><span id="total-blocks">0</span> total</div>
            </div>

            <div class="card">
                <div class="card-title">System CPU</div>
                <div class="card-value" id="cpu-percent">0</div>
                <div class="card-subtitle">% usage</div>
            </div>

            <div class="card">
                <div class="card-title">Memory</div>
                <div class="card-value" id="memory-percent">0</div>
                <div class="card-subtitle">% usage</div>
            </div>

            <div class="card">
                <div class="card-title">Baseline Mean</div>
                <div class="card-value" id="baseline-mean">0</div>
                <div class="card-subtitle">req/60s</div>
            </div>

            <div class="card">
                <div class="card-title">Baseline StdDev</div>
                <div class="card-value" id="baseline-stddev">0</div>
                <div class="card-subtitle">σ</div>
            </div>

            <div class="card">
                <div class="card-title">Uptime</div>
                <div class="card-value" id="uptime">0</div>
                <div class="card-subtitle">seconds</div>
            </div>
        </div>

        <!-- Top IPs -->
        <div class="table-container">
            <div class="table-header">
                <h2>🔴 Top Attacking IPs</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Rate (req/60s)</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="top-ips-table">
                    <tr>
                        <td colspan="3" class="empty">No data yet</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Alerts Log -->
        <div class="alert-log">
            <div class="alert-log-header">
                <h2>📋 Recent Alerts</h2>
            </div>
            <div id="alerts-list">
                <div class="empty">
                    <p>Waiting for alerts...</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer>
            <p>HNG Anomaly Detection Engine | Real-time Security Monitoring</p>
        </footer>
    </div>

    <script>
        // Auto-refresh every 3 seconds
        const REFRESH_INTERVAL = 3000;

        async function updateMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();

                // Update KPI cards
                document.getElementById('global-rate').textContent = data.global_rate.toFixed(1);
                document.getElementById('active-blocks').textContent = data.active_blocks;
                document.getElementById('total-blocks').textContent = data.total_blocks;
                document.getElementById('cpu-percent').textContent = data.cpu_percent.toFixed(1);
                document.getElementById('memory-percent').textContent = data.memory_percent.toFixed(1);
                document.getElementById('baseline-mean').textContent = data.baseline_mean.toFixed(1);
                document.getElementById('baseline-stddev').textContent = data.baseline_stddev.toFixed(1);
                document.getElementById('uptime').textContent = formatUptime(data.uptime_seconds);

                // Update status badge
                const badge = document.getElementById('status-badge');
                badge.textContent = '● ONLINE';
                badge.className = 'status-badge';

                // Color code CPU/memory
                if (data.cpu_percent > 80) {
                    document.getElementById('cpu-percent').parentElement.parentElement.classList.add('critical');
                } else if (data.cpu_percent > 60) {
                    document.getElementById('cpu-percent').parentElement.parentElement.classList.add('warning');
                }

                // Update top IPs
                updateTopIPs(data.top_ips);

                // Update timestamp
                const now = new Date();
                document.getElementById('last-update').textContent = now.toLocaleTimeString();

            } catch (error) {
                console.error('Failed to fetch metrics:', error);
                document.getElementById('status-badge').textContent = '● OFFLINE';
                document.getElementById('status-badge').classList.add('critical');
            }
        }

        async function updateAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const data = await response.json();

                const alertsList = document.getElementById('alerts-list');

                if (data.alerts.length === 0) {
                    alertsList.innerHTML = '<div class="empty"><p>No alerts yet</p></div>';
                    return;
                }

                let html = '';
                for (const alert of data.alerts) {
                    const decision = alert.decision || 'unknown';
                    const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
                    html += `
                        <div class="alert-entry ${decision}">
                            <span class="alert-ip">${alert.source_ip}</span>
                            <span class="alert-decision ${decision}">${decision.toUpperCase()}</span>
                            <span class="alert-time">${time}</span>
                        </div>
                    `;
                }
                alertsList.innerHTML = html;

            } catch (error) {
                console.error('Failed to fetch alerts:', error);
            }
        }

        function updateTopIPs(topIPs) {
            const tbody = document.getElementById('top-ips-table');

            if (!topIPs || topIPs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="empty">No attacking IPs</td></tr>';
                return;
            }

            let html = '';
            for (const ip of topIPs.slice(0, 10)) {
                const rate = ip.rate || 0;
                let rateClass = 'rate-low';
                if (rate > 100) rateClass = 'rate-high';
                else if (rate > 50) rateClass = 'rate-medium';

                html += `
                    <tr>
                        <td class="ip-addr">${ip.ip}</td>
                        <td class="${rateClass}">${rate.toFixed(0)}</td>
                        <td>Monitoring</td>
                    </tr>
                `;
            }
            tbody.innerHTML = html;
        }

        function formatUptime(seconds) {
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = Math.floor(seconds % 60);
            return `${h}h ${m}m ${s}s`;
        }

        // Initial load
        updateMetrics();
        updateAlerts();

        // Refresh every 3 seconds
        setInterval(() => {
            updateMetrics();
            updateAlerts();
        }, REFRESH_INTERVAL);
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_dashboard(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False):
    """Start the dashboard server."""
    app = create_app()
    logger.info(
        "Starting dashboard on http://%s:%d",
        host if host != "0.0.0.0" else "localhost",
        port,
    )
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_dashboard(debug=False)
