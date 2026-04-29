"""
detector/blocker.py — IP blocklist management and enforcement.

Responsibilities:
  - Track which IPs are blocked and why
  - Apply iptables DROP rules to the kernel
  - Manage TTL and expiration of blocks
  - Handle unbanning (TTL expiry, manual override)
  - Log all actions for audit trail
  - Ensure idempotency (no duplicate rules, safe concurrent access)

Design constraints:
  - Runs inside Docker container; iptables runs on host
  - For testing/lab: use subprocess to call iptables (requires --privileged)
  - For production: push blocks to a host-level agent or Redis
  - Never block localhost (127.0.0.1, ::1)
  - Verify every rule was actually added (check iptables output)
"""

import os
import time
import json
import logging
import subprocess
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How long (seconds) to block an IP before auto-unban
DEFAULT_BLOCK_TTL = 3600  # 1 hour

# Never block these IPs
PROTECTED_IPS = {
    "127.0.0.1",      # localhost (IPv4)
    "::1",            # localhost (IPv6)
    "0.0.0.0",        # any (IPv4)
    "::",             # any (IPv6)
}

# iptables chain name for our blocks
CHAIN_NAME = "HNG_ANOMALY_BLOCKS"

# Blocklist file path (used for persistence across container restarts)
BLOCKLIST_FILE = "/tmp/hng_blocklist.json"

# Lock file to prevent concurrent modifications
LOCK_FILE = "/tmp/hng_blocklist.lock"
LOCK_TIMEOUT = 5.0  # seconds


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class BlockAction(Enum):
    """The action taken on an IP."""
    LOG_ONLY   = "log"      # Logged but not blocked
    RATE_LIMIT = "limit"    # Application-level 429 (future)
    DROP       = "drop"     # iptables DROP rule


@dataclass(frozen=True)
class BlockRecord:
    """One IP's block status and metadata."""
    source_ip:       str
    action:          BlockAction
    reason:          str            # e.g. "z_score=7.2"
    detected_at:     float          # Unix timestamp
    blocked_at:      Optional[float] = None    # when rule was applied
    ttl_seconds:     int = DEFAULT_BLOCK_TTL
    score:           float = 0.0    # the anomaly score that triggered this

    @property
    def expires_at(self) -> float:
        """Unix timestamp when this block expires."""
        if self.blocked_at is None:
            return self.detected_at + self.ttl_seconds
        return self.blocked_at + self.ttl_seconds

    @property
    def is_expired(self) -> float:
        """True if the block has outlived its TTL."""
        return time.time() > self.expires_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())


# ---------------------------------------------------------------------------
# Blocklist manager
# ---------------------------------------------------------------------------

class BlocklistManager:
    """
    Manages IP blocks: tracking, persisting, applying to kernel.

    Thread-safe: uses a file-level lock for concurrent access.

    Usage:
        manager = BlocklistManager()
        manager.block_ip("1.2.3.4", reason="z_score=5.2", action=BlockAction.DROP)
        manager.unblock_ip("1.2.3.4")
        manager.cleanup_expired()
    """

    def __init__(self, blocklist_file=BLOCKLIST_FILE, lock_file=LOCK_FILE):
        self._blocklist_file = blocklist_file
        self._lock_file      = lock_file
        self._lock           = threading.Lock()
        self._loaded_cache   = None
        self._cache_time     = 0

    # ------------------------------------------------------------------
    # Public: block/unblock operations
    # ------------------------------------------------------------------

    def block_ip(
        self,
        source_ip: str,
        reason: str,
        action: BlockAction = BlockAction.DROP,
        score: float = 0.0,
        ttl_seconds: int = DEFAULT_BLOCK_TTL,
        now: Optional[float] = None,
    ) -> BlockRecord:
        """
        Add an IP to the blocklist. Applies kernel rule if action=DROP.

        Idempotency: if IP is already blocked, updates the record
        (reason, score, TTL) and re-applies the rule if needed.

        Args:
            source_ip:    IP string to block
            reason:       Human-readable reason (e.g. "z_score=5.2")
            action:       BlockAction.LOG, .RATE_LIMIT, or .DROP
            score:        The anomaly score that triggered this
            ttl_seconds:  How long before auto-unban
            now:          Unix timestamp (injectable for testing)

        Returns:
            The BlockRecord that was stored
        """
        now = now if now is not None else time.time()

        if self._is_protected(source_ip):
            logger.warning(
                "Attempted to block protected IP: %s — ignored", source_ip
            )
            return None

        with self._acquire_lock():
            blocklist = self._load()

            # If already blocked, update the record
            if source_ip in blocklist:
                old = blocklist[source_ip]
                logger.info(
                    "IP already blocked, updating: %s reason=%s",
                    source_ip, reason,
                )
            else:
                logger.info(
                    "New block: ip=%s reason=%s action=%s score=%.2f",
                    source_ip, reason, action.value, score,
                )

            record = BlockRecord(
                source_ip=source_ip,
                action=action,
                reason=reason,
                detected_at=now,
                blocked_at=now if action == BlockAction.DROP else None,
                ttl_seconds=ttl_seconds,
                score=score,
            )

            blocklist[source_ip] = record
            self._save(blocklist)

            # Apply kernel rule if blocking at network level
            if action == BlockAction.DROP:
                self._apply_iptables_rule(source_ip)

            return record

    def unblock_ip(self, source_ip: str, now: Optional[float] = None) -> bool:
        """
        Remove an IP from the blocklist and remove its iptables rule.

        Returns True if the IP was blocked and is now unblocked.
        Returns False if the IP was not in the blocklist.
        """
        now = now if now is not None else time.time()

        with self._acquire_lock():
            blocklist = self._load()

            if source_ip not in blocklist:
                return False

            record = blocklist[source_ip]
            del blocklist[source_ip]
            self._save(blocklist)

            if record.action == BlockAction.DROP:
                self._remove_iptables_rule(source_ip)

            logger.info("Unblocked: ip=%s (ttl expired or manual)", source_ip)
            return True

    def is_blocked(self, source_ip: str) -> bool:
        """Check if an IP is currently blocked (not expired)."""
        with self._acquire_lock():
            blocklist = self._load()
            if source_ip not in blocklist:
                return False
            record = blocklist[source_ip]
            return not record.is_expired

    def get_record(self, source_ip: str) -> Optional[BlockRecord]:
        """Retrieve the BlockRecord for an IP, or None if not blocked."""
        with self._acquire_lock():
            blocklist = self._load()
            record = blocklist.get(source_ip)
            if record and record.is_expired:
                return None
            return record

    def list_active(self) -> List[BlockRecord]:
        """Return all currently active blocks (not expired)."""
        with self._acquire_lock():
            blocklist = self._load()
            return [
                r for r in blocklist.values()
                if not r.is_expired
            ]

    def cleanup_expired(self, now: Optional[float] = None) -> int:
        """
        Remove all expired blocks from the list and kernel.

        Called periodically (e.g. every 60 seconds) by a background thread.
        Returns the number of blocks that were cleaned up.
        """
        now = now if now is not None else time.time()

        with self._acquire_lock():
            blocklist = self._load()
            expired = [
                ip for ip, record in blocklist.items()
                if record.is_expired
            ]

            for ip in expired:
                record = blocklist[ip]
                if record.action == BlockAction.DROP:
                    self._remove_iptables_rule(ip)
                del blocklist[ip]

            if expired:
                self._save(blocklist)
                logger.info("Cleaned up %d expired blocks", len(expired))

            return len(expired)

    # ------------------------------------------------------------------
    # Internal: file I/O and locking
    # ------------------------------------------------------------------

    def _load(self) -> Dict[str, BlockRecord]:
        """
        Load blocklist from file. Returns empty dict if file doesn't exist.

        Called while holding the lock.
        """
        if not os.path.exists(self._blocklist_file):
            return {}

        try:
            with open(self._blocklist_file, "r") as f:
                data = json.load(f)
            # Deserialise JSON back into BlockRecord objects
            return {
                ip: BlockRecord(
                    source_ip=ip,
                    action=BlockAction(r["action"]),
                    reason=r["reason"],
                    detected_at=r["detected_at"],
                    blocked_at=r.get("blocked_at"),
                    ttl_seconds=r.get("ttl_seconds", DEFAULT_BLOCK_TTL),
                    score=r.get("score", 0.0),
                )
                for ip, r in data.items()
            }
        except Exception as exc:
            logger.error("Failed to load blocklist: %s", exc)
            return {}

    def _save(self, blocklist: Dict[str, BlockRecord]) -> None:
        """
        Write blocklist to file.

        Called while holding the lock.
        """
        try:
            data = {
                ip: asdict(record)
                for ip, record in blocklist.items()
            }
            # Convert BlockAction enum to string for JSON
            for record_dict in data.values():
                record_dict["action"] = record_dict["action"].value

            with open(self._blocklist_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save blocklist: %s", exc)

    def _acquire_lock(self):
        """Context manager for file-level locking."""
        return _FileLock(self._lock_file, timeout=LOCK_TIMEOUT)

    # ------------------------------------------------------------------
    # Internal: iptables integration
    # ------------------------------------------------------------------

    def _apply_iptables_rule(self, source_ip: str) -> bool:
        """
        Add an iptables DROP rule for source_ip.

        Idempotency: checks if rule already exists before adding.

        Returns True if rule was added or already exists.
        Returns False if there was an error.
        """
        # Ensure chain exists
        if not self._chain_exists():
            if not self._create_chain():
                logger.error("Failed to create iptables chain")
                return False

        # Check if rule already exists
        if self._rule_exists(source_ip):
            logger.debug("iptables rule already exists for %s", source_ip)
            return True

        # Add the rule
        cmd = [
            "iptables", "-I", CHAIN_NAME, "1",
            "-s", source_ip,
            "-j", "DROP",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error(
                    "iptables failed: %s | stderr: %s",
                    " ".join(cmd), result.stderr,
                )
                return False

            logger.info("iptables rule added: %s DROP", source_ip)
            return True

        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out")
            return False
        except Exception as exc:
            logger.error("iptables error: %s", exc)
            return False

    def _remove_iptables_rule(self, source_ip: str) -> bool:
        """
        Remove an iptables DROP rule for source_ip.

        Returns True if rule was removed or didn't exist.
        """
        if not self._rule_exists(source_ip):
            return True

        cmd = [
            "iptables", "-D", CHAIN_NAME,
            "-s", source_ip,
            "-j", "DROP",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error(
                    "iptables removal failed: %s | stderr: %s",
                    " ".join(cmd), result.stderr,
                )
                return False

            logger.info("iptables rule removed: %s", source_ip)
            return True

        except Exception as exc:
            logger.error("iptables removal error: %s", exc)
            return False

    def _rule_exists(self, source_ip: str) -> bool:
        """Check if an iptables rule for source_ip already exists."""
        cmd = [
            "iptables", "-C", CHAIN_NAME,
            "-s", source_ip,
            "-j", "DROP",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _chain_exists(self) -> bool:
        """Check if our custom iptables chain exists."""
        cmd = ["iptables", "-L", CHAIN_NAME, "-n"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _create_chain(self) -> bool:
        """Create our custom iptables chain."""
        cmd = ["iptables", "-N", CHAIN_NAME]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Created iptables chain: %s", CHAIN_NAME)
                return True

            # Check if chain already exists (race condition)
            if "already exists" in result.stderr or self._chain_exists():
                return True

            logger.error("Failed to create chain: %s", result.stderr)
            return False

        except Exception as exc:
            logger.error("iptables chain creation error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal: safety checks
    # ------------------------------------------------------------------

    def _is_protected(self, source_ip: str) -> bool:
        """Return True if source_ip should never be blocked."""
        return source_ip in PROTECTED_IPS


# ---------------------------------------------------------------------------
# File locking helper
# ---------------------------------------------------------------------------

class _FileLock:
    """Context manager for file-level locking using a lock file."""

    def __init__(self, lock_file: str, timeout: float = 5.0):
        self._lock_file = lock_file
        self._timeout   = timeout
        self._acquired  = False

    def __enter__(self):
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            try:
                # Atomic file creation — only succeeds if file doesn't exist
                fd = os.open(
                    self._lock_file,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o644,
                )
                os.close(fd)
                self._acquired = True
                return self
            except FileExistsError:
                time.sleep(0.01)

        logger.warning("Lock acquisition timed out after %.1fs", self._timeout)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._acquired:
            try:
                os.unlink(self._lock_file)
            except Exception:
                pass
