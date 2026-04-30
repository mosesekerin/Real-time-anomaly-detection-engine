"""
tests/test_unbanner.py — Tests for the auto-unban system.

Coverage:
  - Violation recording and escalation
  - Backoff schedule (10m → 30m → 2h → permanent)
  - 24-hour reset window
  - Scheduled unban processing
  - Manual overrides (force_unban, reset_counter)
  - File persistence
"""

import os
import json
import time
import pytest
import tempfile
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.unbanner import (
    UnbannerManager, ViolationHistory, Violation, BanStatus,
    BACKOFF_SCHEDULE, VIOLATION_RESET_WINDOW, MAX_VIOLATIONS_BEFORE_PERMANENT,
)


@pytest.fixture
def temp_history_file():
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
def mock_blocker():
    """Mock BlocklistManager."""
    blocker = MagicMock()
    blocker.unblock_ip.return_value = True
    return blocker


@pytest.fixture
def unbanner(mock_blocker, temp_history_file, temp_lock_file):
    return UnbannerManager(
        mock_blocker,
        history_file=temp_history_file,
        lock_file=temp_lock_file,
    )


class TestViolationRecording:

    def test_first_violation_scheduled_10min(self, unbanner):
        """First violation → scheduled for 10 minutes."""
        now = 100_000.0
        record = unbanner.record_violation("1.2.3.4", "z_score=5.2", 5.2, now=now)

        assert record.violation_count == 1
        assert record.ban_status == BanStatus.SCHEDULED
        assert record.current_backoff_idx == 0
        assert record.scheduled_unban_at == now + BACKOFF_SCHEDULE[0]

    def test_second_violation_escalates_30min(self, unbanner):
        """Second violation within 24h → escalate to 30 minutes."""
        now = 100_000.0

        # First violation
        unbanner.record_violation("1.2.3.4", "z_score=5.2", 5.2, now=now)

        # Second violation 1 minute later
        record = unbanner.record_violation(
            "1.2.3.4",
            "z_score=5.5",
            5.5,
            now=now + 60,
        )

        assert record.violation_count == 2
        assert record.current_backoff_idx == 1
        assert record.scheduled_unban_at == (now + 60) + BACKOFF_SCHEDULE[1]

    def test_third_violation_escalates_2hours(self, unbanner):
        """Third violation within 24h → escalate to 2 hours."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)
        unbanner.record_violation("1.2.3.4", "z=5.5", 5.5, now=now + 60)
        record = unbanner.record_violation(
            "1.2.3.4", "z=5.8", 5.8, now=now + 120
        )

        assert record.violation_count == 3
        assert record.current_backoff_idx == 2
        assert record.scheduled_unban_at == (now + 120) + BACKOFF_SCHEDULE[2]

    def test_fourth_violation_permanent(self, unbanner):
        """Fourth violation within 24h → permanent ban."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)
        unbanner.record_violation("1.2.3.4", "z=5.5", 5.5, now=now + 60)
        unbanner.record_violation("1.2.3.4", "z=5.8", 5.8, now=now + 120)
        record = unbanner.record_violation(
            "1.2.3.4", "z=6.0", 6.0, now=now + 180
        )

        assert record.violation_count == 4
        assert record.is_permanent
        assert record.ban_status == BanStatus.PERMANENT


class TestViolationResetWindow:

    def test_violations_reset_after_24_hours(self, unbanner):
        """
        First violation at t=0.
        Second violation at t=0+23h → escalate.
        Third violation at t=0+25h → reset counter, treat as first violation.
        """
        now = 100_000.0

        # First violation
        r1 = unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)
        assert r1.violation_count == 1

        # Second violation 23h later (within window)
        r2 = unbanner.record_violation(
            "1.2.3.4",
            "z=5.5",
            5.5,
            now=now + (23 * 3600),
        )
        assert r2.violation_count == 2

        # Third violation 25h after first (outside window) → reset
        r3 = unbanner.record_violation(
            "1.2.3.4",
            "z=5.8",
            5.8,
            now=now + (25 * 3600),
        )
        assert r3.violation_count == 1
        assert r3.current_backoff_idx == 0  # Back to 10 min


class TestScheduledUnbanProcessing:

    def test_process_unbans_executes_scheduled(self, unbanner, mock_blocker):
        """process_scheduled_unbans() executes unbans at their scheduled time."""
        now = 100_000.0

        # Record a violation → scheduled for now + 10min
        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)

        # Process at scheduled time
        unbanned = unbanner.process_scheduled_unbans(now=now + BACKOFF_SCHEDULE[0])

        assert unbanned == 1
        mock_blocker.unblock_ip.assert_called()

    def test_process_unbans_skips_early(self, unbanner, mock_blocker):
        """process_scheduled_unbans() skips unbans not yet due."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)

        # Process before scheduled time
        unbanned = unbanner.process_scheduled_unbans(now=now + 60)

        assert unbanned == 0
        mock_blocker.unblock_ip.assert_not_called()

    def test_process_unbans_changes_status(self, unbanner):
        """After unban, status changes from SCHEDULED to UNBANNED."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)

        # Before processing
        record = unbanner.get_history("1.2.3.4")
        assert record.is_scheduled

        # After processing
        unbanner.process_scheduled_unbans(now=now + BACKOFF_SCHEDULE[0])
        record = unbanner.get_history("1.2.3.4")
        assert record.ban_status == BanStatus.UNBANNED

    def test_multiple_unbans_in_one_call(self, unbanner, mock_blocker):
        """Process multiple scheduled unbans at once."""
        now = 100_000.0

        unbanner.record_violation("1.1.1.1", "z=5.2", 5.2, now=now)
        unbanner.record_violation("2.2.2.2", "z=5.3", 5.3, now=now + 10)

        unbanned = unbanner.process_scheduled_unbans(
            now=now + BACKOFF_SCHEDULE[0] + 100
        )

        assert unbanned == 2
        assert mock_blocker.unblock_ip.call_count == 2


class TestManualOverrides:

    def test_force_unban_removes_block(self, unbanner, mock_blocker):
        """force_unban() removes the block and resets counter."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)
        record_before = unbanner.get_history("1.2.3.4")
        assert record_before.violation_count == 1

        # Force unban
        result = unbanner.force_unban("1.2.3.4", reason="admin override", now=now)

        assert result is True
        mock_blocker.unblock_ip.assert_called_with("1.2.3.4", now=now)

        # Counter reset
        record_after = unbanner.get_history("1.2.3.4")
        assert record_after.violation_count == 0

    def test_force_unban_nonexistent_ip(self, unbanner):
        """force_unban() on unknown IP returns False."""
        result = unbanner.force_unban("9.9.9.9")
        assert result is False

    def test_reset_counter_keeps_block(self, unbanner, mock_blocker):
        """reset_violation_counter() clears violations but doesn't remove block."""
        now = 100_000.0

        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=now)
        unbanner.reset_violation_counter("1.2.3.4", reason="server fixed")

        record = unbanner.get_history("1.2.3.4")
        assert record.violation_count == 0
        # Block is NOT removed (blocker.unblock_ip not called)
        mock_blocker.unblock_ip.assert_not_called()


class TestFilePersistence:

    def test_violations_persist_across_restart(self, mock_blocker,
                                               temp_history_file, temp_lock_file):
        """Violation history survives manager restart."""
        # Manager 1: record violations
        u1 = UnbannerManager(mock_blocker, temp_history_file, temp_lock_file)
        u1.record_violation("1.2.3.4", "z=5.2", 5.2, now=100_000.0)
        u1.record_violation("1.2.3.4", "z=5.5", 5.5, now=100_060.0)

        # Manager 2: reload from same file
        u2 = UnbannerManager(mock_blocker, temp_history_file, temp_lock_file)
        record = u2.get_history("1.2.3.4")

        assert record is not None
        assert record.violation_count == 2
        assert record.current_backoff_idx == 1

    def test_json_format_valid(self, unbanner):
        unbanner.record_violation("1.2.3.4", "z=5.2", 5.2, now=100_000.0)

        with open(unbanner._history_file, "r") as f:
            data = json.load(f)

        assert "1.2.3.4" in data
        assert data["1.2.3.4"]["ban_status"] == "scheduled"
        assert len(data["1.2.3.4"]["violations"]) == 1

    def test_corrupted_file_handled(self, mock_blocker, temp_history_file,
                                     temp_lock_file):
        # Write invalid JSON
        with open(temp_history_file, "w") as f:
            f.write("{ invalid json")

        # Should not crash
        u = UnbannerManager(mock_blocker, temp_history_file, temp_lock_file)
        active = u.list_active_bans()
        assert active == []


class TestListOperations:

    def test_list_active_bans(self, unbanner):
        unbanner.record_violation("1.1.1.1", "z=5.2", 5.2, now=100_000.0)
        unbanner.record_violation("2.2.2.2", "z=5.3", 5.3, now=100_010.0)

        active = unbanner.list_active_bans()
        assert len(active) == 2
        assert all(r.ban_status in (BanStatus.ACTIVE, BanStatus.SCHEDULED) 
                   for r in active)

    def test_list_permanent_bans(self, unbanner):
        now = 100_000.0
        for i in range(4):
            unbanner.record_violation("1.2.3.4", f"z=5.{i}", 5.0 + i * 0.1,
                                      now=now + i * 60)

        permanent = unbanner.list_permanent_bans()
        assert len(permanent) == 1
        assert permanent[0].source_ip == "1.2.3.4"
        assert permanent[0].is_permanent


class TestViolationDataclass:

    def test_violation_history_frozen(self):
        record = ViolationHistory(
            source_ip="1.2.3.4",
            ban_status=BanStatus.SCHEDULED,
        )
        with pytest.raises(AttributeError):
            record.source_ip = "5.6.7.8"

    def test_time_until_unban_property(self):
        now = 100_000.0
        unban_at = now + 600  # 10 minutes
        record = ViolationHistory(
            source_ip="1.2.3.4",
            ban_status=BanStatus.SCHEDULED,
            scheduled_unban_at=unban_at,
        )
        # Can't directly test because it uses time.time()
        # But ensure the property doesn't crash
        remaining = record.time_until_unban
        assert remaining is not None


class TestEdgeCases:

    def test_permanent_ban_stays_permanent(self, unbanner):
        """Once permanent, can't escalate further."""
        now = 100_000.0
        for i in range(5):  # Try 5 violations
            record = unbanner.record_violation(
                "1.2.3.4",
                f"z=5.{i}",
                5.0 + i * 0.1,
                now=now + i * 60,
            )

        assert record.is_permanent
        # All 5 violations recorded, but status is permanent after 4th
        assert record.violation_count == 5

    def test_different_ips_tracked_independently(self, unbanner):
        now = 100_000.0

        # IP A: 1 violation
        unbanner.record_violation("1.1.1.1", "z=5.2", 5.2, now=now)

        # IP B: 3 violations
        for i in range(3):
            unbanner.record_violation("2.2.2.2", "z=5.2", 5.2, now=now + i * 60)

        record_a = unbanner.get_history("1.1.1.1")
        record_b = unbanner.get_history("2.2.2.2")

        assert record_a.violation_count == 1
        assert record_b.violation_count == 3

    def test_empty_history_on_startup(self, unbanner):
        """New unbanner with no history should be empty."""
        active = unbanner.list_active_bans()
        permanent = unbanner.list_permanent_bans()

        assert active == []
        assert permanent == []
