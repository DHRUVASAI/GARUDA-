import tempfile
from pathlib import Path
from backend.app.services.adaptive_intel import AdaptiveIntelController
from backend.app.services.web3_retry_queue import Web3RetryQueue, estimate_eip1559_fees


def test_adaptive_intel_poisoning_resistance_and_persistence():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "adaptive_state.json"
        ctrl = AdaptiveIntelController(state_path=p)
        # Simulate 50 consecutive false-positive poisoning attempts
        for i in range(50):
            ctrl.record_false_positive(i, f"poison-{i}.local", "analyst")
        # Must never exceed max_threshold (0.88)
        assert ctrl.base_threshold <= 0.88
        assert p.exists()

        # Reload from disk and verify state persisted across restart
        ctrl2 = AdaptiveIntelController(state_path=p)
        assert ctrl2.base_threshold == ctrl.base_threshold
        assert len(ctrl2.false_positive_history) == 50


def test_web3_retry_queue_and_eip1559_fees():
    with tempfile.TemporaryDirectory() as td:
        qp = Path(td) / "queue.json"
        q = Web3RetryQueue(path=qp)
        q.enqueue("0x" + "ab" * 32, block_height=10, event_count=5, chain="monad")
        assert q.pending_count() == 1

        # Simulate offline RPC (returns False)
        res_fail = q.flush(lambda item: False)
        assert res_fail["submitted"] == 0 and res_fail["remaining"] == 1

        # Simulate RPC recovery (returns True)
        res_ok = q.flush(lambda item: True)
        assert res_ok["submitted"] == 1 and res_ok["remaining"] == 0

        fees = estimate_eip1559_fees(base_fee_gwei=20.0, priority_gwei=2.0)
        assert fees["maxPriorityFeePerGas"] == 2_000_000_000
        assert fees["maxFeePerGas"] == 42_000_000_000
