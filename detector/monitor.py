"""
monitor.py — Orchestrates the tailer and parser into a single monitoring loop.

Responsibilities:
  - Wire FileTailer → parse_line → emit to registered handlers
  - Track and periodically report parse failure metrics
  - Provide a clean shutdown interface (SIGTERM / SIGINT safe)
  - Dead-letter logging: write unparseable lines to a separate file for triage
  - Never let a handler exception crash the monitor loop

Architecture note:
  Handlers are synchronous callbacks. If you need async processing (e.g. writing
  to a queue, calling an HTTP endpoint), run the monitor in a thread and have
  handlers enqueue work rather than doing IO inline.
"""

import logging
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .parser import LogEntry, ParseFailure, parse_line
from .tailer import FileTailer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Handler type
# ---------------------------------------------------------------------------

# A handler receives a fully parsed LogEntry. It must not raise.
HandlerFn = Callable[[LogEntry], None]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class MonitorMetrics:
    lines_read:       int = 0
    lines_parsed_ok:  int = 0
    lines_failed:     int = 0
    handler_errors:   int = 0
    uptime_start:     float = field(default_factory=time.monotonic)

    @property
    def failure_rate(self) -> float:
        if self.lines_read == 0:
            return 0.0
        return self.lines_failed / self.lines_read

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.uptime_start

    def summary(self) -> str:
        return (
            f"uptime={self.uptime_seconds:.0f}s | "
            f"read={self.lines_read} | "
            f"ok={self.lines_parsed_ok} | "
            f"failed={self.lines_failed} "
            f"({self.failure_rate:.1%}) | "
            f"handler_errors={self.handler_errors}"
        )


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class NginxLogMonitor:
    """
    Continuously monitors an Nginx JSON access log.

    Usage:
        def on_entry(entry: LogEntry):
            print(entry.source_ip, entry.status)

        monitor = NginxLogMonitor("/var/log/nginx/hng-access.log")
        monitor.add_handler(on_entry)
        monitor.run()   # blocks; catches SIGINT/SIGTERM for clean shutdown

    Or run in a thread:
        t = threading.Thread(target=monitor.run, daemon=True)
        t.start()
        # ... later ...
        monitor.stop()
    """

    def __init__(
        self,
        log_path: str = "/var/log/nginx/hng-access.log",
        dead_letter_path: Optional[str] = "/var/log/nginx/hng-access.dead.log",
        metrics_interval: float = 60.0,
        poll_interval: float = 0.5,
    ):
        """
        Args:
            log_path:          Path to the Nginx access log (from Docker volume).
            dead_letter_path:  Where to write unparseable lines for later triage.
                               Set to None to disable dead-letter logging.
            metrics_interval:  How often (seconds) to log a metrics summary.
            poll_interval:     How often the tailer polls for new lines when idle.
        """
        self.log_path = log_path
        self.dead_letter_path = dead_letter_path
        self.metrics_interval = metrics_interval

        self._handlers: List[HandlerFn] = []
        self._metrics = MonitorMetrics()
        self._stop_event = threading.Event()
        self._line_counter = 0

        self._tailer = FileTailer(log_path, poll_interval=poll_interval)

        # Register OS signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def add_handler(self, fn: HandlerFn) -> None:
        """Register a callback to receive each successfully parsed LogEntry."""
        self._handlers.append(fn)
        logger.debug("Registered handler: %s", getattr(fn, "__name__", type(fn).__name__))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the monitoring loop. Blocks until stop() is called or a fatal
        tailer error occurs.
        """
        logger.info(
            "NginxLogMonitor starting. log=%s dead_letter=%s",
            self.log_path,
            self.dead_letter_path,
        )

        metrics_thread = threading.Thread(
            target=self._metrics_reporter, daemon=True, name="metrics-reporter"
        )
        metrics_thread.start()

        try:
            for raw_line in self._tailer.tail():
                if self._stop_event.is_set():
                    break
                self._process_line(raw_line)

        except RuntimeError as exc:
            # Tailer gave up after max retries
            logger.critical("Tailer fatal error: %s", exc)
            raise

        finally:
            logger.info("NginxLogMonitor stopped. %s", self._metrics.summary())

    def stop(self) -> None:
        """Signal the monitor loop to exit cleanly after the current line."""
        logger.info("Stop requested.")
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal: line processing
    # ------------------------------------------------------------------

    def _process_line(self, raw_line: str) -> None:
        self._line_counter += 1
        self._metrics.lines_read += 1

        result = parse_line(raw_line, line_num=self._line_counter)

        if isinstance(result, ParseFailure):
            self._metrics.lines_failed += 1
            self._handle_parse_failure(result)
            return

        self._metrics.lines_parsed_ok += 1
        self._dispatch(result)

    def _dispatch(self, entry: LogEntry) -> None:
        """Call each registered handler, catching and counting any exceptions."""
        for handler in self._handlers:
            try:
                handler(entry)
            except Exception as exc:
                self._metrics.handler_errors += 1
                logger.error(
                    "Handler %s raised %s: %s",
                    getattr(handler, "__name__", type(handler).__name__),
                    type(exc).__name__,
                    exc,
                    exc_info=False,  # don't spam full tracebacks for transient errors
                )

    def _handle_parse_failure(self, failure: ParseFailure) -> None:
        """
        Log failures at DEBUG level to avoid flooding production logs.
        Write them to the dead-letter file for offline triage.
        """
        logger.debug(
            "Parse failure [line %s]: %s | raw=%r",
            failure.line_num,
            failure.reason,
            failure.raw_line[:120],  # truncate for readability
        )

        if self.dead_letter_path:
            self._write_dead_letter(failure)

        # Escalate if the failure rate goes above 10% — indicates a format change
        if (
            self._metrics.lines_read % 1000 == 0
            and self._metrics.failure_rate > 0.10
        ):
            logger.warning(
                "High parse failure rate: %.1f%% — verify log format matches parser.",
                self._metrics.failure_rate * 100,
            )

    def _write_dead_letter(self, failure: ParseFailure) -> None:
        """Append unparseable lines to the dead-letter file. Never raises."""
        try:
            with open(self.dead_letter_path, "a", encoding="utf-8") as dlf:
                dlf.write(
                    f"[line={failure.line_num}] [reason={failure.reason}] "
                    f"{failure.raw_line}\n"
                )
        except Exception as exc:
            # Dead-letter write failure is non-fatal; don't let it stop the loop
            logger.error("Could not write to dead-letter log: %s", exc)

    # ------------------------------------------------------------------
    # Internal: metrics reporter
    # ------------------------------------------------------------------

    def _metrics_reporter(self) -> None:
        """Background thread that logs a metrics summary every N seconds."""
        while not self._stop_event.is_set():
            time.sleep(self.metrics_interval)
            logger.info("METRICS | %s", self._metrics.summary())

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_signal(self, signum, frame) -> None:
        logger.info("Received signal %d — initiating graceful shutdown.", signum)
        self.stop()
