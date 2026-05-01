"""
detector/main.py — Production daemon using actual FileTailer API (FIXED).
"""

import os
import sys
import time
import logging
import threading
import queue
import signal
import traceback
import psutil

from detector.tailer import FileTailer
from detector.parser import parse_line
from detector.sliding_window import SlidingWindow
from detector.baseline import BaselineEngine
from detector.detector import AnomalyDetector, Decision
from detector.blocker import BlocklistManager, BlockAction
from detector.unbanner import UnbannerManager
from detector.slack_alerter import get_slack_alerter
from detector.metrics_writer import MetricsWriter
from detector.dashboard import run_dashboard

# Configuration
NGINX_LOG_PATH = os.environ.get("NGINX_LOG_PATH", "logs/test-access.log")
PARSE_QUEUE_SIZE = 1000
DETECT_QUEUE_SIZE = 1000
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
ENABLE_SLACK = os.environ.get("ENABLE_SLACK", "false").lower() == "true"
ENABLE_DASHBOARD = os.environ.get("ENABLE_DASHBOARD", "true").lower() == "true"
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))
MEMORY_WARNING_PERCENT = 80.0
QUEUE_WARNING_SIZE = 500

# Logging setup
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("logs/detector.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("detector")

# Thread: LogTailer (uses FileTailer.tail() iterator)
class LogTailerThread(threading.Thread):
    """Tail logs using FileTailer.tail() iterator."""

    def __init__(self, log_path: str, parse_queue: queue.Queue, shutdown_event: threading.Event):
        super().__init__(name="LogTailer", daemon=False)
        self.log_path = log_path
        self.parse_queue = parse_queue
        self.shutdown_event = shutdown_event
        self.lines_read = 0
        self.errors = 0

    def run(self):
        """Main loop: use FileTailer.tail() iterator."""
        logger.info("LogTailer started | log_path=%s", self.log_path)

        try:
            tailer = FileTailer(self.log_path)
            
            # tail() returns a generator that yields lines
            for line in tailer.tail():
                if self.shutdown_event.is_set():
                    break
                
                try:
                    self.lines_read += 1
                    self.parse_queue.put(line, timeout=5.0)

                    if self.lines_read % 1000 == 0:
                        logger.debug("LogTailer | lines_read=%d", self.lines_read)

                    if self.parse_queue.qsize() > QUEUE_WARNING_SIZE:
                        logger.warning("LogTailer | parse_queue backing up | size=%d", self.parse_queue.qsize())

                except queue.Full:
                    logger.error("LogTailer | parse_queue full, dropping line")
                    self.errors += 1

        except KeyboardInterrupt:
            logger.info("LogTailer interrupted")
        except Exception as exc:
            logger.error("LogTailer crashed: %s\n%s", exc, traceback.format_exc())
            self.errors += 1
        finally:
            logger.info("LogTailer stopped | lines_read=%d errors=%d", self.lines_read, self.errors)

# Thread: Parser
class ParserThread(threading.Thread):
    """Parse JSON log entries."""

    def __init__(self, parse_queue: queue.Queue, detect_queue: queue.Queue, shutdown_event: threading.Event):
        super().__init__(name="Parser", daemon=False)
        self.parse_queue = parse_queue
        self.detect_queue = detect_queue
        self.shutdown_event = shutdown_event
        self.entries_parsed = 0
        self.entries_failed = 0

    def run(self):
        """Main loop: parse lines."""
        logger.info("Parser started")

        try:
            while not self.shutdown_event.is_set():
                try:
                    line = self.parse_queue.get(timeout=1.0)
                    result = parse_line(line)

                    if result.success:
                        self.entries_parsed += 1
                        self.detect_queue.put(result.entry, timeout=5.0)
                    else:
                        self.entries_failed += 1

                except queue.Empty:
                    pass
                except queue.Full:
                    logger.error("Parser | detect_queue full")
                    self.entries_failed += 1

        except Exception as exc:
            logger.error("Parser crashed: %s", exc)
        finally:
            logger.info("Parser stopped | parsed=%d failures=%d", self.entries_parsed, self.entries_failed)

# Thread: Detector
class DetectorThread(threading.Thread):
    """Main anomaly detection."""

    def __init__(self, detect_queue, shutdown_event, window, baseline, detector, blocker, unbanner, slack=None):
        super().__init__(name="Detector", daemon=False)
        self.detect_queue = detect_queue
        self.shutdown_event = shutdown_event
        self.window = window
        self.baseline = baseline
        self.detector = detector
        self.blocker = blocker
        self.unbanner = unbanner
        self.slack = slack
        self.entries_evaluated = 0
        self.blocks_issued = 0
        self.flags_issued = 0
        self.errors = 0

    def run(self):
        """Main loop: detect anomalies."""
        logger.info("Detector started")

        try:
            while not self.shutdown_event.is_set():
                try:
                    entry = self.detect_queue.get(timeout=1.0)
                    now = time.time()

                    self.window.record(entry.source_ip, entry.timestamp)
                    current_rate = self.window.ip_rate(entry.source_ip, as_of=now)
                    global_rate = self.window.global_rate(as_of=now)
                    ip_stats = self.baseline.get_stats(entry.source_ip, now=now)

                    result = self.detector.evaluate(
                        source_ip=entry.source_ip,
                        current_rate=current_rate,
                        error_count=1 if entry.status >= 400 else 0,
                        total_count=1,
                        global_rate=global_rate,
                        now=now,
                    )

                    self.entries_evaluated += 1

                    if result.decision == Decision.BLOCK:
                        self.blocks_issued += 1
                        self.blocker.block_ip(entry.source_ip, reason=result.dominant_signal().name, action=BlockAction.DROP, score=result.max_score, ttl_seconds=600)
                        self.unbanner.record_violation(entry.source_ip, reason=result.dominant_signal().name, score=result.max_score)
                        self.detector.record_flag(entry.source_ip, now=now)

                        if self.slack:
                            try:
                                self.slack.send_alert(source_ip=entry.source_ip, decision="block", anomaly_score=result.max_score, dominant_signal=result.dominant_signal().name, current_rate=current_rate, baseline_mean=ip_stats.mean, baseline_stddev=ip_stats.stddev, reasons=result.reasons, ban_duration_seconds=600)
                            except Exception as e:
                                logger.error("Slack alert failed: %s", e)

                    elif result.decision == Decision.FLAG:
                        self.flags_issued += 1
                        if self.slack:
                            try:
                                self.slack.send_alert(source_ip=entry.source_ip, decision="flag", anomaly_score=result.max_score, dominant_signal=result.dominant_signal().name, current_rate=current_rate, baseline_mean=ip_stats.mean, baseline_stddev=ip_stats.stddev, reasons=result.reasons)
                            except Exception as e:
                                logger.error("Slack alert failed: %s", e)

                    if self.entries_evaluated % 100 == 0:
                        logger.debug("Detector | evaluated=%d blocks=%d flags=%d", self.entries_evaluated, self.blocks_issued, self.flags_issued)

                except queue.Empty:
                    pass
                except Exception as exc:
                    logger.error("Detector error: %s", exc)
                    self.errors += 1

        except Exception as exc:
            logger.error("Detector crashed: %s", exc)
        finally:
            logger.info("Detector stopped | evaluated=%d blocks=%d flags=%d", self.entries_evaluated, self.blocks_issued, self.flags_issued)

# Thread: BackgroundTasks
class BackgroundTasksThread(threading.Thread):
    """Periodic maintenance."""

    def __init__(self, shutdown_event, baseline, unbanner, blocker, window, slack=None):
        super().__init__(name="BackgroundTasks", daemon=True)
        self.shutdown_event = shutdown_event
        self.baseline = baseline
        self.unbanner = unbanner
        self.blocker = blocker
        self.window = window
        self.slack = slack
        self.start_time = time.time()
        self.iterations = 0

    def run(self):
        """Main loop: every 60 seconds."""
        logger.info("BackgroundTasks started")

        try:
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(60.0)
                if self.shutdown_event.is_set():
                    break

                try:
                    now = time.time()
                    self.iterations += 1

                    self.baseline.recalculate(now=now)
                    unbanned = self.unbanner.process_scheduled_unbans(now=now)
                    expired = self.blocker.cleanup_expired(now=now)

                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    memory = psutil.virtual_memory()

                    if memory.percent > MEMORY_WARNING_PERCENT:
                        logger.warning("HealthCheck | HIGH MEMORY: %.1f%%", memory.percent)

                    if self.iterations % 60 == 0:
                        uptime_hours = (now - self.start_time) / 3600
                        logger.info("HealthCheck | uptime=%.1fh cpu=%.1f%% memory=%.1f%%", uptime_hours, cpu_percent, memory.percent)

                    global_rate = self.window.global_rate(as_of=now)
                    snapshot = self.window.ip_snapshot(as_of=now)
                    top_ips = sorted([{"ip": ip, "rate": rate} for ip, rate in snapshot.items()], key=lambda x: x["rate"], reverse=True)[:10]
                    global_stats = self.baseline.get_stats("__global__", now=now)

                    try:
                        MetricsWriter.write_metrics(global_rate=global_rate, top_ips=top_ips, baseline_mean=global_stats.mean, baseline_stddev=global_stats.stddev, now=now)
                    except Exception as e:
                        logger.error("Failed to write metrics: %s", e)

                    logger.info("BackgroundTasks | iteration=%d unbanned=%d expired=%d", self.iterations, unbanned, expired)

                except Exception as exc:
                    logger.error("BackgroundTasks error: %s", exc)

        finally:
            logger.info("BackgroundTasks stopped | iterations=%d", self.iterations)

# Thread: Dashboard
class DashboardThread(threading.Thread):
    """Flask HTTP server."""

    def __init__(self, shutdown_event, port):
        super().__init__(name="Dashboard", daemon=True)
        self.shutdown_event = shutdown_event
        self.port = port

    def run(self):
        """Start Flask."""
        logger.info("Dashboard starting on port %d", self.port)
        try:
            run_dashboard(host="0.0.0.0", port=self.port, debug=False)
        except Exception as exc:
            logger.error("Dashboard error: %s", exc)
        finally:
            logger.info("Dashboard stopped")

# Main daemon
class AnomalyDetectorDaemon:
    """Multi-threaded anomaly detection daemon."""

    def __init__(self):
        self.shutdown_event = threading.Event()
        self.threads = []

    def start(self):
        """Start the daemon."""
        logger.info("=" * 80)
        logger.info("HNG ANOMALY DETECTION DAEMON STARTING")
        logger.info("=" * 80)

        try:
            logger.info("Initializing components...")
            window = SlidingWindow(window_seconds=60)
            baseline = BaselineEngine(window)
            detector = AnomalyDetector(window, baseline)
            blocker = BlocklistManager()
            unbanner = UnbannerManager(blocker)
            slack = get_slack_alerter() if ENABLE_SLACK else None

            logger.info("Components initialized")

            parse_queue = queue.Queue(maxsize=PARSE_QUEUE_SIZE)
            detect_queue = queue.Queue(maxsize=DETECT_QUEUE_SIZE)

            logger.info("Starting threads...")

            tailer = LogTailerThread(NGINX_LOG_PATH, parse_queue, self.shutdown_event)
            self.threads.append(tailer)
            tailer.start()

            parser = ParserThread(parse_queue, detect_queue, self.shutdown_event)
            self.threads.append(parser)
            parser.start()

            detector_th = DetectorThread(detect_queue, self.shutdown_event, window, baseline, detector, blocker, unbanner, slack)
            self.threads.append(detector_th)
            detector_th.start()

            background = BackgroundTasksThread(self.shutdown_event, baseline, unbanner, blocker, window, slack)
            self.threads.append(background)
            background.start()

            if ENABLE_DASHBOARD:
                dashboard = DashboardThread(self.shutdown_event, DASHBOARD_PORT)
                self.threads.append(dashboard)
                dashboard.start()
                logger.info("Dashboard enabled on port %d", DASHBOARD_PORT)

            logger.info("All threads started")
            logger.info("=" * 80)
            logger.info("DAEMON RUNNING — Press Ctrl+C to stop")
            logger.info("=" * 80)

            for thread in self.threads:
                thread.join()

        except KeyboardInterrupt:
            logger.info("Received SIGINT, shutting down...")
            self.shutdown()

    def shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down daemon...")
        self.shutdown_event.set()

        timeout = 10.0
        start = time.time()
        for thread in self.threads:
            remaining = timeout - (time.time() - start)
            if remaining > 0:
                thread.join(timeout=remaining)

        logger.info("=" * 80)
        logger.info("DAEMON STOPPED")
        logger.info("=" * 80)

def main():
    """Entry point."""
    def signal_handler(sig, frame):
        daemon.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    daemon = AnomalyDetectorDaemon()
    daemon.start()

if __name__ == "__main__":
    main()
