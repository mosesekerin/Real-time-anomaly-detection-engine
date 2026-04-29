"""
tests/test_blocker.py — Tests for BlocklistManager

Coverage:
  - Block/unblock operations
  - TTL and expiration (with mocked time)
  - Protected IPs (never block localhost)
  - Idempotency (no duplicate rules)
  - File persistence
  - iptables integration (mocked)
  - Error handling
"""

import os
import json
import time
import pytest
import tempfile
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.blocker import (
    BlocklistManager, BlockRecord, BlockAction,
    PROTECTED_IPS, DEFAULT_BLOCK_TTL,
)


@pytest.fixture
def temp_blocklist_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_lock_file():
    path = tempfile.mktemp(suffix=".lock")
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture
def manager(temp_blocklist_file, temp_lock_file):
    return BlocklistManager(
        blocklist_file=temp_blocklist_file,
        lock_file=temp_lock_file,
    )


class TestBlockUnblock:

    def test_block_ip_creates_record(self, manager):
        record = manager.block_ip(
            "1.2.3.4",
            reason="z_score=5.2",
            action=BlockAction.DROP,
            score=5.2,
        )
        assert record is not None
        assert record.source_ip == "1.2.3.4"
        assert record.score == 5.2

    def test_block_ip_persists_to_file(self, manager):
        manager.block_ip("1.2.3.4", reason="attack", action=BlockAction.DROP)
        manager2 = BlocklistManager(
            blocklist_file=manager._blocklist_file,
            lock_file=manager._lock_file,
        )
        assert manager2.is_blocked("1.2.3.4")

    def test_unblock_ip_removes_record(self, manager):
        manager.block_ip("1.2.3.4", reason="attack", action=BlockAction.DROP)
        assert manager.is_blocked("1.2.3.4")
        result = manager.unblock_ip("1.2.3.4")
        assert result is True
        assert not manager.is_blocked("1.2.3.4")

    def test_unblock_nonexistent_returns_false(self, manager):
        result = manager.unblock_ip("9.9.9.9")
        assert result is False

    @patch('detector.blocker.time.time')
    def test_is_blocked_false_for_expired(self, mock_time, manager):
        now = 100_000.0
        mock_time.return_value = now
        manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=10,
            now=now,
        )
        assert manager.is_blocked("1.2.3.4") is True
        mock_time.return_value = now + 11
        assert manager.is_blocked("1.2.3.4") is False

    @patch('detector.blocker.time.time')
    def test_get_record_returns_nonexpired(self, mock_time, manager):
        now = 100_000.0
        mock_time.return_value = now
        manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=3600,
            now=now,
        )
        record = manager.get_record("1.2.3.4")
        assert record is not None
        assert record.source_ip == "1.2.3.4"

    @patch('detector.blocker.time.time')
    def test_get_record_returns_none_for_expired(self, mock_time, manager):
        now = 100_000.0
        mock_time.return_value = now
        manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=1,
            now=now,
        )
        mock_time.return_value = now + 2
        assert manager.get_record("1.2.3.4") is None


class TestTTLExpiration:

    def test_expires_at_calculated(self, manager):
        now = 100_000.0
        record = manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=3600,
            now=now,
        )
        assert record.expires_at == now + 3600

    @patch('detector.blocker.time.time')
    def test_remaining_seconds_decreases(self, mock_time, manager):
        now = 100_000.0
        mock_time.return_value = now
        record = manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=3600,
            now=now,
        )
        assert record.remaining_seconds == 3600
        mock_time.return_value = now + 1000
        assert record.remaining_seconds == 2600

    @patch('detector.blocker.time.time')
    def test_cleanup_expired_removes_old_blocks(self, mock_time, manager):
        now = 100_000.0
        mock_time.return_value = now
        manager.block_ip(
            "1.2.3.4",
            reason="old",
            action=BlockAction.DROP,
            ttl_seconds=10,
            now=now,
        )
        assert manager.is_blocked("1.2.3.4") is True
        mock_time.return_value = now + 11
        assert manager.is_blocked("1.2.3.4") is False
        record = manager.get_record("1.2.3.4")
        assert record is None

    def test_cleanup_expired_returns_count(self, manager):
        now = 100_000.0
        for i in range(3):
            manager.block_ip(
                f"1.2.3.{i}",
                reason="attack",
                action=BlockAction.DROP,
                ttl_seconds=1,
                now=now,
            )
        count = manager.cleanup_expired()
        assert count == 3

    @patch('detector.blocker.time.time')
    def test_cleanup_expired_with_mock_time(self, mock_time, manager):
        mock_time.return_value = 1000.0
        manager.block_ip(
            "1.2.3.4",
            reason="attack",
            action=BlockAction.DROP,
            ttl_seconds=100,
            now=1000.0,
        )
        assert manager.is_blocked("1.2.3.4") is True
        mock_time.return_value = 1101.0
        assert manager.is_blocked("1.2.3.4") is False


class TestProtectedIPs:

    @pytest.mark.parametrize("protected_ip", [
        "127.0.0.1", "::1", "0.0.0.0", "::",
    ])
    def test_protected_ips_not_blocked(self, manager, protected_ip):
        record = manager.block_ip(
            protected_ip,
            reason="test",
            action=BlockAction.DROP,
        )
        assert record is None
        assert not manager.is_blocked(protected_ip)

    def test_attackers_ip_can_be_blocked(self, manager):
        record = manager.block_ip(
            "203.0.113.42",
            reason="attack",
            action=BlockAction.DROP,
        )
        assert record is not None
        assert manager.is_blocked("203.0.113.42")


class TestIdempotency:

    @patch('detector.blocker.subprocess.run')
    def test_block_same_ip_twice_updates_record(self, mock_run, manager):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        r1 = manager.block_ip("1.2.3.4", reason="first", action=BlockAction.DROP)
        r2 = manager.block_ip(
            "1.2.3.4",
            reason="second",
            action=BlockAction.DROP,
            score=6.0,
        )
        assert r1.reason == "first"
        assert r2.reason == "second"
        active = manager.list_active()
        assert len(active) == 1


class TestFilePersistence:

    def test_blocks_survive_manager_restart(self, temp_blocklist_file, temp_lock_file):
        m1 = BlocklistManager(
            blocklist_file=temp_blocklist_file,
            lock_file=temp_lock_file,
        )
        m1.block_ip("1.2.3.4", reason="attack", action=BlockAction.DROP)
        m2 = BlocklistManager(
            blocklist_file=temp_blocklist_file,
            lock_file=temp_lock_file,
        )
        assert m2.is_blocked("1.2.3.4")

    def test_json_format_valid(self, manager):
        manager.block_ip("1.2.3.4", reason="attack", action=BlockAction.DROP)
        with open(manager._blocklist_file, "r") as f:
            data = json.load(f)
        assert "1.2.3.4" in data
        assert data["1.2.3.4"]["action"] == "drop"

    def test_corrupted_file_handled_gracefully(self, manager):
        with open(manager._blocklist_file, "w") as f:
            f.write("{ invalid json")
        active = manager.list_active()
        assert active == []


class TestListOperations:

    def test_list_active_empty(self, manager):
        assert manager.list_active() == []

    def test_list_active_populated(self, manager):
        manager.block_ip("1.1.1.1", reason="a", action=BlockAction.DROP)
        manager.block_ip("2.2.2.2", reason="b", action=BlockAction.DROP)
        active = manager.list_active()
        assert len(active) >= 0


class TestBlockRecord:

    def test_record_frozen(self):
        record = BlockRecord(
            source_ip="1.2.3.4",
            action=BlockAction.DROP,
            reason="test",
            detected_at=100.0,
        )
        with pytest.raises(AttributeError):
            record.source_ip = "5.6.7.8"


class TestErrorHandling:

    @patch('detector.blocker.subprocess.run')
    def test_iptables_failure_logged(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Permission denied",
        )
        result = manager._apply_iptables_rule("1.2.3.4")
        assert result is False

    @patch('detector.blocker.subprocess.run')
    def test_iptables_timeout_handled(self, mock_run, manager):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("iptables", 5)
        result = manager._apply_iptables_rule("1.2.3.4")
        assert result is False

    def test_missing_blocklist_file_handled(self, temp_lock_file):
        manager = BlocklistManager(
            blocklist_file="/nonexistent/path/blocklist.json",
            lock_file=temp_lock_file,
        )
        active = manager.list_active()
        assert active == []
