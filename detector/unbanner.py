"""
detector/unbanner.py — Auto-unban system with violation history and backoff.

Responsibilities:
  - Track violation history per IP (count + timestamps)
  - Determine backoff TTL based on violation count
  - Schedule unban events (via background task)
  - Remove iptables rules safely
  - Reset counters after clean period (24 hours)
  - Prevent permanent bans from auto-unbanning

Backoff schedule:
  Violation 1 → 10 minutes
  Violation 2 → 30 minutes (within 24 hours of violation 1)
  Violation 3 → 2 hours (within 24 hours of violation 2)
  Violation 4+ → PERMANENT (manual review only)

Design pattern:
  The blocker calls block_ip() which returns a BlockRecord with TTL.
  The unbanner watches that TTL and schedules unban at expiry.
  If the IP violates again before unban, escalate the TTL.
"""

import json
import time
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Backoff times (seconds)
BACKOFF_SCHEDULE = [
    10 * 60,      # 10 minutes
    30 * 60,      # 30 minutes
    2 * 3600,     # 2 hours
    # 4th+ violation → permanent (no TTL)
]

# How long to track an IP before resetting violation counter
VIOLATION_RESET_WINDOW = 24 * 3600  # 24 hours

# Maximum violations before permanent ban
MAX_VIOLATIONS_BEFORE_PERMANENT = len(BACKOFF_SCHEDULE)

# Violation history file
VIOLATION_HISTORY_FILE = "/tmp/hng_violation_history.json"
VIOLATION_LOCK_FILE = "/tmp/hng_violation_history.lock"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class BanStatus(Enum):
    """Current status of an IP's ban."""
    ACTIVE      = "active"       # Currently blocked in iptables
    SCHEDULED   = "scheduled"    # Will unban at scheduled_unban_time
    UNBANNED    = "unbanned"     # Recently unbanned, tracking violations
    PERMANENT   = "permanent"    # Manual review required


@dataclass(frozen=True)
class Violation:
    """One violation event."""
    timestamp:     float          # When the violation occurred
    reason:        str            # What triggered the block (e.g. "z_score=5.2")
    score:         float          # The anomaly score


@dataclass(frozen=True)
class ViolationHistory:
    """Complete violation record for one IP."""
    source_ip:           str
    violations:          List[Violation] = field(default_factory=list)
    ban_status:          BanStatus = BanStatus.UNBANNED
    current_backoff_idx: int = 0      # Index into BACKOFF_SCHEDULE
    scheduled_unban_at:  Optional[float] = None  # When to unban (or None)
    first_violation_at:  Optional[float] = None  # Timestamp of first violation in current window
    blocked_at:          Optional[float] = None  # When iptables rule was added

    @property
    def violation_count(self) -> int:
        """Total violations in the current reset window."""
        if not self.first_violation_at:
            return 0
        # Simple: count violations since first_violation_at (within reset window)
        # If first_violation_at is None, counter is 0
        # The unbanner.py code handles resetting first_violation_at after 24h
        return len(self.violations)

    @property
    def is_permanent(self) -> bool:
        return self.ban_status == BanStatus.PERMANENT

    @property
    def is_scheduled(self) -> bool:
        return self.ban_status == BanStatus.SCHEDULED

    @property
    def is_active(self) -> bool:
        return self.ban_status == BanStatus.ACTIVE

    @property
    def time_until_unban(self) -> Optional[float]:
        """Seconds until scheduled unban, or None if not scheduled."""
        if self.scheduled_unban_at is None:
            return None
        return max(0.0, self.scheduled_unban_at - time.time())


# ---------------------------------------------------------------------------
# Unbanner manager
# ---------------------------------------------------------------------------

class UnbannerManager:
    """
    Manages violation history and auto-unban scheduling.

    Usage:
        unbanner = UnbannerManager(blocker_manager)
        
        # Called when detector blocks an IP
        unbanner.record_violation(ip, reason, score)
        
        # Called every 60s from background thread
        unbanner.process_scheduled_unbans()
        
        # Called by manual admin action
        unbanner.force_unban(ip)
    """

    def __init__(self, blocker_manager, history_file=VIOLATION_HISTORY_FILE,
                 lock_file=VIOLATION_LOCK_FILE):
        """
        Args:
            blocker_manager: BlocklistManager instance to call unblock_ip()
            history_file:    Path to JSON violation history
            lock_file:       Path to lock file for concurrent access
        """
        self._blocker        = blocker_manager
        self._history_file   = history_file
        self._lock_file      = lock_file
        self._lock           = threading.Lock()
        self._loaded_cache   = None
        self._cache_time     = 0

    # ------------------------------------------------------------------
    # Public: violation recording and queries
    # ------------------------------------------------------------------

    def record_violation(
        self,
        source_ip: str,
        reason: str,
        score: float,
        now: Optional[float] = None,
    ) -> ViolationHistory:
        """
        Record a violation for source_ip. Escalates TTL if repeat offender.

        Called by the detector handler when it decides to BLOCK.

        Returns:
            Updated ViolationHistory for this IP.
        """
        now = now if now is not None else time.time()

        with self._acquire_lock():
            history = self._load()

            # Create or load history for this IP
            if source_ip not in history:
                history[source_ip] = ViolationHistory(source_ip=source_ip)

            record = history[source_ip]

            # Check if we should reset the counter
            if record.first_violation_at is None:
                # First violation ever
                new_record = ViolationHistory(
                    source_ip=source_ip,
                    violations=[Violation(timestamp=now, reason=reason, score=score)],
                    ban_status=BanStatus.SCHEDULED,
                    current_backoff_idx=0,
                    scheduled_unban_at=now + BACKOFF_SCHEDULE[0],
                    first_violation_at=now,
                    blocked_at=now,
                )
                logger.info(
                    "First violation recorded: ip=%s reason=%s score=%.2f | "
                    "scheduled unban in %d min",
                    source_ip, reason, score, BACKOFF_SCHEDULE[0] // 60,
                )
            elif (now - record.first_violation_at) > VIOLATION_RESET_WINDOW:
                # More than 24 hours since first violation — reset counter
                new_record = ViolationHistory(
                    source_ip=source_ip,
                    violations=[Violation(timestamp=now, reason=reason, score=score)],
                    ban_status=BanStatus.SCHEDULED,
                    current_backoff_idx=0,
                    scheduled_unban_at=now + BACKOFF_SCHEDULE[0],
                    first_violation_at=now,
                    blocked_at=now,
                )
                logger.info(
                    "Violation counter reset (24h passed): ip=%s | "
                    "new violation, scheduled unban in %d min",
                    source_ip, BACKOFF_SCHEDULE[0] // 60,
                )
            else:
                # Within 24-hour window — escalate backoff
                violation_count = record.violation_count + 1
                
                if violation_count > MAX_VIOLATIONS_BEFORE_PERMANENT:
                    # Permanent ban
                    new_record = ViolationHistory(
                        source_ip=source_ip,
                        violations=record.violations + [
                            Violation(timestamp=now, reason=reason, score=score)
                        ],
                        ban_status=BanStatus.PERMANENT,
                        current_backoff_idx=MAX_VIOLATIONS_BEFORE_PERMANENT,
                        first_violation_at=record.first_violation_at,
                        blocked_at=record.blocked_at,
                    )
                    logger.warning(
                        "PERMANENT BAN: ip=%s | %d violations in 24h | "
                        "manual review required",
                        source_ip, violation_count,
                    )
                else:
                    # Escalate to next backoff level
                    next_idx = min(violation_count - 1, len(BACKOFF_SCHEDULE) - 1)
                    ttl = BACKOFF_SCHEDULE[next_idx]
                    new_record = ViolationHistory(
                        source_ip=source_ip,
                        violations=record.violations + [
                            Violation(timestamp=now, reason=reason, score=score)
                        ],
                        ban_status=BanStatus.SCHEDULED,
                        current_backoff_idx=next_idx,
                        scheduled_unban_at=now + ttl,
                        first_violation_at=record.first_violation_at,
                        blocked_at=record.blocked_at,
                    )
                    logger.warning(
                        "Violation escalated: ip=%s | violation #%d → %d min ban | "
                        "next unban at %s",
                        source_ip,
                        violation_count,
                        ttl // 60,
                        datetime.fromtimestamp(now + ttl, tz=timezone.utc)
                        .strftime("%H:%M:%S"),
                    )

            history[source_ip] = new_record
            self._save(history)
            return new_record

    def get_history(self, source_ip: str) -> Optional[ViolationHistory]:
        """Retrieve the violation history for an IP."""
        with self._acquire_lock():
            history = self._load()
            return history.get(source_ip)

    def list_active_bans(self) -> List[ViolationHistory]:
        """Return all IPs currently in ACTIVE or SCHEDULED status."""
        with self._acquire_lock():
            history = self._load()
            return [
                record for record in history.values()
                if record.ban_status in (BanStatus.ACTIVE, BanStatus.SCHEDULED)
            ]

    def list_permanent_bans(self) -> List[ViolationHistory]:
        """Return all IPs with permanent bans (manual review required)."""
        with self._acquire_lock():
            history = self._load()
            return [
                record for record in history.values()
                if record.is_permanent
            ]

    # ------------------------------------------------------------------
    # Public: unban operations
    # ------------------------------------------------------------------

    def process_scheduled_unbans(self, now: Optional[float] = None) -> int:
        """
        Check all scheduled unbans and execute those whose time has come.

        Called every 60 seconds from a background thread.
        Returns the number of IPs that were unbanned.
        """
        now = now if now is not None else time.time()
        unbanned_count = 0

        with self._acquire_lock():
            history = self._load()
            to_unban = []

            for ip, record in history.items():
                if (record.is_scheduled and 
                    record.scheduled_unban_at is not None and
                    now >= record.scheduled_unban_at):
                    to_unban.append(ip)

            for ip in to_unban:
                # Remove from blocker
                self._blocker.unblock_ip(ip, now=now)

                # Update history
                record = history[ip]
                updated = ViolationHistory(
                    source_ip=ip,
                    violations=record.violations,
                    ban_status=BanStatus.UNBANNED,
                    current_backoff_idx=record.current_backoff_idx,
                    first_violation_at=record.first_violation_at,
                    blocked_at=record.blocked_at,
                )
                history[ip] = updated

                logger.info(
                    "Auto-unban executed: ip=%s | violations=%d | next violation resets",
                    ip, record.violation_count,
                )
                unbanned_count += 1

            if to_unban:
                self._save(history)

        return unbanned_count

    def force_unban(
        self,
        source_ip: str,
        reason: str = "manual override",
        now: Optional[float] = None,
    ) -> bool:
        """
        Manually unban an IP (including permanent bans).

        Returns True if unban succeeded, False if IP wasn't blocked.
        """
        now = now if now is not None else time.time()

        with self._acquire_lock():
            history = self._load()

            if source_ip not in history:
                return False

            record = history[source_ip]

            # Remove from blocker
            self._blocker.unblock_ip(source_ip, now=now)

            # Reset history
            new_record = ViolationHistory(
                source_ip=source_ip,
                violations=[],
                ban_status=BanStatus.UNBANNED,
                current_backoff_idx=0,
                first_violation_at=None,
                blocked_at=None,
            )
            history[source_ip] = new_record
            self._save(history)

            logger.warning(
                "Manual unban: ip=%s | reason=%s | violation counter reset",
                source_ip, reason,
            )
            return True

    def reset_violation_counter(
        self,
        source_ip: str,
        reason: str = "admin reset",
        now: Optional[float] = None,
    ) -> bool:
        """
        Clear violation history for an IP without removing the iptables rule.

        Used when an IP legitimizes after being banned (e.g., admin fixes their server).
        """
        now = now if now is not None else time.time()

        with self._acquire_lock():
            history = self._load()

            if source_ip not in history:
                return False

            new_record = ViolationHistory(
                source_ip=source_ip,
                violations=[],
                ban_status=BanStatus.UNBANNED,
                current_backoff_idx=0,
                first_violation_at=None,
                blocked_at=None,
            )
            history[source_ip] = new_record
            self._save(history)

            logger.info(
                "Violation counter reset: ip=%s | reason=%s",
                source_ip, reason,
            )
            return True

    # ------------------------------------------------------------------
    # Internal: file I/O and locking
    # ------------------------------------------------------------------

    def _load(self) -> Dict[str, ViolationHistory]:
        """Load violation history from file."""
        if not self._history_file or not __import__('os').path.exists(self._history_file):
            return {}

        try:
            with open(self._history_file, "r") as f:
                data = json.load(f)

            return {
                ip: ViolationHistory(
                    source_ip=ip,
                    violations=[
                        Violation(
                            timestamp=v["timestamp"],
                            reason=v["reason"],
                            score=v["score"],
                        )
                        for v in record["violations"]
                    ],
                    ban_status=BanStatus(record["ban_status"]),
                    current_backoff_idx=record.get("current_backoff_idx", 0),
                    scheduled_unban_at=record.get("scheduled_unban_at"),
                    first_violation_at=record.get("first_violation_at"),
                    blocked_at=record.get("blocked_at"),
                )
                for ip, record in data.items()
            }
        except Exception as exc:
            logger.error("Failed to load violation history: %s", exc)
            return {}

    def _save(self, history: Dict[str, ViolationHistory]) -> None:
        """Write violation history to file."""
        try:
            data = {}
            for ip, record in history.items():
                data[ip] = {
                    "source_ip": record.source_ip,
                    "violations": [
                        {"timestamp": v.timestamp, "reason": v.reason, "score": v.score}
                        for v in record.violations
                    ],
                    "ban_status": record.ban_status.value,
                    "current_backoff_idx": record.current_backoff_idx,
                    "scheduled_unban_at": record.scheduled_unban_at,
                    "first_violation_at": record.first_violation_at,
                    "blocked_at": record.blocked_at,
                }

            with open(self._history_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save violation history: %s", exc)

    def _acquire_lock(self):
        """Context manager for file-level locking."""
        import os
        import contextlib

        @contextlib.contextmanager
        def file_lock():
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    fd = os.open(
                        self._lock_file,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                        0o644,
                    )
                    os.close(fd)
                    break
                except FileExistsError:
                    time.sleep(0.01)

            try:
                yield
            finally:
                try:
                    os.unlink(self._lock_file)
                except FileNotFoundError:
                    pass

        return file_lock()
