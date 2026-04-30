"""Manual detector test"""
from datetime import datetime, timezone
import time

from detector.sliding_window import SlidingWindow
from detector.baseline import BaselineEngine
from detector.detector import AnomalyDetector, Decision
from detector.blocker import BlocklistManager, BlockAction

def ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc)

print("=" * 60)
print("ANOMALY DETECTOR INTEGRATION TEST")
print("=" * 60)

# === PHASE 1: BUILD BASELINE ===
print("\nPHASE 1: Building baseline over 5 cycles...")
window = SlidingWindow(window_seconds=60)
baseline = BaselineEngine(window)

base_time = 100_000.0  # Use fixed time, not current time
for cycle in range(5):
    cycle_time = base_time + cycle * 60
    # Normal IP: 20 req/60s
    for _ in range(20):
        window.record("192.168.1.100", ts(cycle_time - 1))
    # Global traffic: 100 req/60s across all IPs
    for i in range(80):
        window.record(f"user_{i}", ts(cycle_time - 1))
    baseline.recalculate(now=cycle_time)
    print(f"  Cycle {cycle+1}/5: {20+80} total requests")

print("\nBaseline built. Moving to evaluation phase...")

# === PHASE 2: EVALUATE AGAINST BASELINE ===
print("\n" + "=" * 60)
print("SCENARIO 1: Normal traffic (should ALLOW)")
print("=" * 60)

detector = AnomalyDetector(window, baseline)
blocker = BlocklistManager()

# Evaluate at time when baseline is stable
eval_time = base_time + 5 * 60

result = detector.evaluate(
    source_ip="192.168.1.100",
    current_rate=20.0,      # Same as baseline mean
    error_count=0,
    total_count=20,
    global_rate=100.0,      # Same as baseline mean
    now=eval_time,
)
print(f"Decision: {result.decision.value}")
print(f"Score: {result.max_score:.2f}")
print(f"Reasons: {result.reasons}")
if result.decision != Decision.ALLOW:
    print(f"WARNING: Expected ALLOW but got {result.decision.value}")
    print(f"Signals: {[(s.name, s.score) for s in result.signals]}")
else:
    print("✓ PASSED")

print("\n" + "=" * 60)
print("SCENARIO 2: Attack traffic (should BLOCK)")
print("=" * 60)

result = detector.evaluate(
    source_ip="10.0.0.99",
    current_rate=300.0,     # 15× baseline (20)
    error_count=0,
    total_count=300,
    global_rate=200.0,      # 2× baseline (100)
    now=eval_time,
)
print(f"Decision: {result.decision.value}")
print(f"Score: {result.max_score:.2f}")
print(f"Dominant signal: {result.dominant_signal().name}")
if result.decision == Decision.BLOCK:
    blocker.block_ip(
        result.source_ip,
        reason=result.dominant_signal().name,
        action=BlockAction.DROP,
        score=result.max_score,
    )
    print(f"Blocked: {blocker.is_blocked('10.0.0.99')}")
    print("✓ PASSED")
else:
    print(f"WARNING: Expected BLOCK but got {result.decision.value}")

print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)
