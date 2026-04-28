"""
tests/test_sliding_window.py
"""
import pytest
from datetime import datetime, timezone
from detector.sliding_window import SlidingWindow, _to_float

def make_ts(unix_epoch: float) -> datetime:
    return datetime.fromtimestamp(unix_epoch, tz=timezone.utc)

def record_at(window, ip, unix_ts):
    window.record(ip, make_ts(unix_ts))

class TestBasicCounting:
    def test_single_request_counted(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.2.3.4", 1000.0)
        assert w.ip_rate("1.2.3.4", as_of=1000.0) == 1

    def test_multiple_requests_same_ip(self):
        w = SlidingWindow(window_seconds=60)
        for i in range(5):
            record_at(w, "1.2.3.4", 1000.0 + i)
        assert w.ip_rate("1.2.3.4", as_of=1059.0) == 5

    def test_unknown_ip_returns_zero(self):
        w = SlidingWindow(window_seconds=60)
        assert w.ip_rate("9.9.9.9") == 0

    def test_global_rate_counts_all_ips(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1001.0)
        record_at(w, "3.3.3.3", 1002.0)
        assert w.global_rate(as_of=1059.0) == 3

    def test_global_rate_same_ip_multiple_times(self):
        w = SlidingWindow(window_seconds=60)
        for i in range(10):
            record_at(w, "1.2.3.4", 1000.0 + i)
        assert w.global_rate(as_of=1059.0) == 10

class TestEviction:
    def test_old_request_evicted_from_ip_window(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.2.3.4", 1000.0)
        record_at(w, "1.2.3.4", 1050.0)
        assert w.ip_rate("1.2.3.4", as_of=1061.0) == 1

    def test_old_request_evicted_from_global_window(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1050.0)
        assert w.global_rate(as_of=1061.0) == 1

    def test_all_requests_evicted(self):
        w = SlidingWindow(window_seconds=60)
        for i in range(10):
            record_at(w, "1.2.3.4", 1000.0 + i)
        assert w.ip_rate("1.2.3.4", as_of=1200.0) == 0
        assert w.global_rate(as_of=1200.0) == 0

    def test_exact_boundary_not_evicted(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.2.3.4", 1000.0)
        # cutoff = 1060 - 60 = 1000.0; condition is < not <=
        assert w.ip_rate("1.2.3.4", as_of=1060.0) == 1

    def test_just_past_boundary_evicted(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.2.3.4", 1000.0)
        assert w.ip_rate("1.2.3.4", as_of=1060.001) == 0

    def test_boundary_burst_not_missed(self):
        w = SlidingWindow(window_seconds=60)
        for _ in range(200):
            record_at(w, "1.2.3.4", 999.0)
        for _ in range(200):
            record_at(w, "1.2.3.4", 1001.0)
        assert w.ip_rate("1.2.3.4", as_of=1001.0) == 400
        assert w.ip_rate("1.2.3.4", as_of=1061.0) == 200

class TestIpIsolation:
    def test_windows_are_independent(self):
        w = SlidingWindow(window_seconds=60)
        for i in range(5):
            record_at(w, "1.1.1.1", 1000.0 + i)
        for i in range(3):
            record_at(w, "2.2.2.2", 1000.0 + i)
        assert w.ip_rate("1.1.1.1", as_of=1059.0) == 5
        assert w.ip_rate("2.2.2.2", as_of=1059.0) == 3

    def test_eviction_of_one_does_not_affect_another(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1050.0)
        assert w.ip_rate("1.1.1.1", as_of=1061.0) == 0
        assert w.ip_rate("2.2.2.2", as_of=1061.0) == 1

    def test_snapshot_only_active_ips(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1000.0)
        snapshot = w.ip_snapshot(as_of=1059.0)
        assert set(snapshot.keys()) == {"1.1.1.1", "2.2.2.2"}

    def test_snapshot_excludes_evicted(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1050.0)
        snapshot = w.ip_snapshot(as_of=1061.0)
        assert "1.1.1.1" not in snapshot
        assert "2.2.2.2" in snapshot

class TestSweepAndCapacity:
    def test_sweep_removes_idle_ips(self):
        w = SlidingWindow(window_seconds=60, evict_interval=10)
        for i in range(10):
            record_at(w, f"10.0.0.{i}", 1000.0)
        for i in range(10):
            record_at(w, "active.ip", 1100.0)
        assert w.tracked_ip_count() == 1

    def test_max_ips_evicts_oldest(self):
        w = SlidingWindow(window_seconds=60, max_ips=3)
        record_at(w, "1.1.1.1", 1000.0)
        record_at(w, "2.2.2.2", 1001.0)
        record_at(w, "3.3.3.3", 1002.0)
        record_at(w, "4.4.4.4", 1003.0)
        assert w.tracked_ip_count() == 3
        assert w.ip_rate("1.1.1.1", as_of=1059.0) == 0
        assert w.ip_rate("4.4.4.4", as_of=1059.0) == 1

class TestTimestampHandling:
    def test_log_timestamp_used_not_parse_time(self):
        w = SlidingWindow(window_seconds=60)
        record_at(w, "1.2.3.4", 900.0)
        record_at(w, "1.2.3.4", 990.0)
        assert w.ip_rate("1.2.3.4", as_of=990.0) == 1

    def test_naive_datetime_does_not_crash(self):
        w = SlidingWindow(window_seconds=60)
        w.record("1.2.3.4", datetime(2025, 4, 28, 12, 0, 0))
        assert w.tracked_ip_count() == 1

    def test_to_float_precision(self):
        dt = make_ts(1714305600.123)
        assert abs(_to_float(dt) - 1714305600.123) < 0.001

class TestHighTraffic:
    def test_high_volume_single_ip(self):
        w = SlidingWindow(window_seconds=60)
        for i in range(1000):
            record_at(w, "attacker", 1000.0 + (i * 0.06))
        assert w.ip_rate("attacker", as_of=1059.9) == 1000

    def test_high_volume_many_ips(self):
        w = SlidingWindow(window_seconds=60)
        for ip_num in range(500):
            for req in range(10):
                record_at(w, f"10.{ip_num//256}.{ip_num%256}.1", 1000.0 + req)
        assert w.global_rate(as_of=1059.0) == 5000
        assert w.tracked_ip_count() == 500
