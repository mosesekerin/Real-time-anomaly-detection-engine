"""
Integration test: full anomaly detection pipeline end-to-end.
"""

import pytest
import tempfile
import os
from datetime import datetime, timezone
from detector.sliding_window import SlidingWindow
from detector.baseline import BaselineEngine
from detector.detector import AnomalyDetector, Decision
from detector.blocker import BlocklistManager, BlockAction
from detector.parser import parse_line

def ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc)

@pytest.fixture
def temp_blocker():
    """Create a blocker with temp files for each test."""
    fd, blocklist_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    lock_path = tempfile.mktemp(suffix=".lock")
    blocker = BlocklistManager(blocklist_file=blocklist_path, lock_file=lock_path)
    yield blocker
    try:
        os.unlink(blocklist_path)
    except:
        pass

class TestFullPipeline:
    
    def test_normal_traffic_allowed(self, temp_blocker):
        """Normal user making normal requests → ALLOW → not blocked"""
        window = SlidingWindow(window_seconds=60)
        baseline = BaselineEngine(window)
        detector = AnomalyDetector(window, baseline)
        blocker = temp_blocker
        
        # Build baseline over 5 cycles (300s)
        for i in range(5):
            now = 100_000.0 + i * 60
            # 10 req/60s from 1.2.3.4 is normal
            for _ in range(10):
                window.record("1.2.3.4", ts(now - 1))
            # 100 req/60s global is normal (from multiple IPs)
            for j in range(90):
                window.record(f"10.0.0.{j % 10}", ts(now - 1))
            baseline.recalculate(now=now)
        
        # Evaluate a normal request
        result = detector.evaluate(
            source_ip="1.2.3.4",
            current_rate=10.0,
            error_count=0,
            total_count=10,
            global_rate=100.0,
            now=100_000.0 + 5 * 60,
        )
        
        # Should be allowed
        assert result.decision == Decision.ALLOW
        # No block action taken, so not in blocklist
        assert not blocker.is_blocked("1.2.3.4")
    
    def test_attacker_blocked_end_to_end(self, temp_blocker):
        """Attacker with high Z-score → BLOCK → IP added to blocklist"""
        window = SlidingWindow(window_seconds=60)
        baseline = BaselineEngine(window)
        detector = AnomalyDetector(window, baseline)
        blocker = temp_blocker
        
        # Build baseline: normal traffic
        for i in range(5):
            now = 100_000.0 + i * 60
            for _ in range(20):
                window.record("1.2.3.4", ts(now - 1))
            for j in range(80):
                window.record(f"10.0.0.{j % 10}", ts(now - 1))
            baseline.recalculate(now=now)
        
        # Evaluate an attack: 200 req/60s from attacker
        result = detector.evaluate(
            source_ip="10.0.0.99",
            current_rate=200.0,
            error_count=0,
            total_count=200,
            global_rate=300.0,
            now=100_000.0 + 5 * 60,
        )
        
        # Should BLOCK
        assert result.decision == Decision.BLOCK
        
        # Actually block the IP
        blocker.block_ip(
            result.source_ip,
            reason=result.dominant_signal().name,
            action=BlockAction.DROP,
            score=result.max_score,
        )
        
        # Verify it's now in the blocklist
        assert blocker.is_blocked("10.0.0.99")
    
    def test_parser_to_detector(self):
        """Log line → parse → sliding window → detect"""
        # Real JSON log line with current timestamp
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        log_line = (
            '{"source_ip":"10.0.0.1",'
            f'"timestamp":"{now_str}",'
            '"method":"GET","path":"/","status":200,"response_size":1024}'
        )
        
        # Parse it
        entry = parse_line(log_line)
        assert entry.source_ip == "10.0.0.1"
        assert entry.status == 200
        
        # Record in sliding window
        window = SlidingWindow()
        window.record(entry.source_ip, entry.timestamp)
        
        # Verify it was counted
        rate = window.ip_rate(entry.source_ip, as_of=entry.timestamp.timestamp())
        assert rate > 0
