"""
tailer.py — Inode-aware, rotation-safe log file tailer.

Responsibilities:
  - Open and continuously read a log file line by line
  - Detect log rotation by comparing inodes
  - Handle file truncation (copytruncate mode)
  - Never block the caller; yields one complete line at a time
  - Never crash on OS-level read errors; backs off and retries

Does NOT parse log content — that is the parser's job.
"""

import os
import time
import logging
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


class LogRotationDetected(Exception):
    """Raised internally when the file on disk is no longer the open handle."""
    pass


class FileTailer:
    """
    Tails a file continuously, surviving log rotation and truncation.

    Usage:
        tailer = FileTailer("/var/log/nginx/hng-access.log")
        for line in tailer.tail():
            process(line)

    The tail() generator never returns under normal operation.
    It yields complete lines (with newline stripped).
    """

    def __init__(
        self,
        path: str,
        poll_interval: float = 0.5,
        reopen_delay: float = 2.0,
        max_reopen_attempts: int = 10,
    ):
        self.path = path
        self.poll_interval = poll_interval
        self.reopen_delay = reopen_delay
        self.max_reopen_attempts = max_reopen_attempts

        self._fh = None
        self._current_inode: Optional[int] = None
        self._first_open = True  # first open seeks to end; reopens after rotation do not

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def tail(self) -> Iterator[str]:
        """
        Infinite generator that yields one complete log line at a time.

        Handles:
          - File not yet existing (waits for creation)
          - Log rotation (rename-based or copytruncate)
          - Transient OS errors (backs off, retries)
        """
        consecutive_failures = 0

        while True:
            try:
                self._open()
                consecutive_failures = 0

                for line in self._read_lines():
                    yield line

            except LogRotationDetected:
                logger.info("Log rotation detected on %s — reopening.", self.path)
                self._close()
                # Do NOT sleep long here: after rename-based rotation the new file
                # may already have data. Reopen quickly and read from position 0.
                time.sleep(0.1)

            except FileNotFoundError:
                logger.warning(
                    "Log file not found: %s — waiting for creation.", self.path
                )
                self._close()
                # When the file is eventually created, read from the beginning —
                # lines may arrive between file creation and our next open().
                self._first_open = False
                time.sleep(self.reopen_delay)
                consecutive_failures += 1

            except PermissionError:
                logger.error(
                    "Permission denied reading %s — check Docker volume mount.", self.path
                )
                self._close()
                time.sleep(self.reopen_delay)
                consecutive_failures += 1

            except OSError as exc:
                logger.error("OS error reading %s: %s", self.path, exc)
                self._close()
                time.sleep(self.reopen_delay)
                consecutive_failures += 1

            if consecutive_failures >= self.max_reopen_attempts:
                logger.critical(
                    "Failed to open %s after %d attempts. Exiting tailer.",
                    self.path,
                    self.max_reopen_attempts,
                )
                raise RuntimeError(
                    f"Could not open {self.path} after {self.max_reopen_attempts} attempts"
                )

    # ------------------------------------------------------------------
    # Internal: file management
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """
        Open the file and record its inode.

        On the very first open we seek to end (tail mode — skip historical lines).
        On every subsequent open (after rotation) we read from position 0 so we
        don't miss lines written to the new file before we detected the rotation.
        """
        self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
        stat = os.stat(self.path)
        self._current_inode = stat.st_ino

        if self._first_open:
            self._fh.seek(0, 2)   # seek to end — skip existing content on startup
            self._first_open = False
        else:
            self._fh.seek(0)      # rotation: read new file from the beginning

        logger.debug(
            "Opened %s (inode=%d, pos=%d)",
            self.path, self._current_inode, self._fh.tell()
        )

    def _close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
            self._current_inode = None

    # ------------------------------------------------------------------
    # Internal: reading
    # ------------------------------------------------------------------

    def _read_lines(self) -> Iterator[str]:
        """
        Read lines from the open handle continuously.

        Checks for rotation on every poll cycle.
        Handles truncation by detecting backward seek position.

        Raises:
            LogRotationDetected: when the file on disk has a different inode.
        """
        partial_line = ""

        while True:
            chunk = self._fh.read(8192)

            if chunk:
                data = partial_line + chunk
                lines = data.split("\n")

                # Last element: "" if chunk ended on newline, or a partial line
                partial_line = lines[-1]

                for line in lines[:-1]:
                    if line:
                        yield line

            else:
                # No new data — check for rotation before sleeping
                self._check_rotation()
                time.sleep(self.poll_interval)

    def _check_rotation(self) -> None:
        """
        Compare the inode of the path on disk with the one we opened.
        Also detect truncation (file is smaller than our current position).

        Raises:
            LogRotationDetected: if inode changed or file was truncated.
            FileNotFoundError:   if the path no longer exists at all.
        """
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            raise LogRotationDetected("File removed — probable rotation in progress")

        if stat.st_ino != self._current_inode:
            raise LogRotationDetected(
                f"Inode changed: was {self._current_inode}, now {stat.st_ino}"
            )

        current_pos = self._fh.tell()
        if stat.st_size < current_pos:
            logger.info(
                "File truncated (%d → %d bytes) — resetting to start.",
                current_pos,
                stat.st_size,
            )
            self._fh.seek(0)
