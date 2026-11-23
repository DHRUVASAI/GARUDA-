"""
GARUDA v10 Ultimate — Web3 Persistent Retry Queue & EIP-1559 Gas Estimator
--------------------------------------------------------------------------
Ensures Merkle root anchor transactions are never lost when an RPC endpoint is offline
or rate-limited, and estimates dynamic EIP-1559 maxFeePerGas / maxPriorityFeePerGas.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

from ..config import DATA_DIR

RETRY_QUEUE_PATH = DATA_DIR / "web3_retry_queue.json"


class Web3RetryQueue:
    def __init__(self, path: Path = RETRY_QUEUE_PATH) -> None:
        self._path = path
        self._queue: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                self._queue = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            self._queue = []

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._queue, indent=2), encoding="utf-8")
        except Exception:
            pass

    def enqueue(self, merkle_root: str, block_height: int, event_count: int, chain: str = "monad") -> Dict[str, Any]:
        item = {
            "merkle_root": merkle_root,
            "block_height": block_height,
            "event_count": event_count,
            "chain": chain,
            "attempts": 0,
            "queued_at": datetime.now(timezone.utc).isoformat(),
        }
        self._queue.append(item)
        self._save()
        return item

    def flush(self, submit_fn: Callable[[Dict[str, Any]], bool]) -> Dict[str, int]:
        """Attempt to resubmit queued anchors. Keeps failed items in queue for next retry."""
        remaining = []
        submitted = 0
        for item in self._queue:
            item["attempts"] = item.get("attempts", 0) + 1
            try:
                if submit_fn(item):
                    submitted += 1
                    continue
            except Exception:
                pass
            remaining.append(item)
        self._queue = remaining
        self._save()
        return {"submitted": submitted, "remaining": len(remaining)}

    def pending_count(self) -> int:
        return len(self._queue)


def estimate_eip1559_fees(base_fee_gwei: float, priority_gwei: float = 1.5) -> Dict[str, int]:
    """Compute EIP-1559 maxFeePerGas = 2 * baseFee + priorityFee (in wei)."""
    base_wei = int(max(0.1, base_fee_gwei) * 1e9)
    prio_wei = int(max(0.1, priority_gwei) * 1e9)
    return {
        "maxPriorityFeePerGas": prio_wei,
        "maxFeePerGas": (2 * base_wei) + prio_wei,
    }


web3_retry_queue = Web3RetryQueue()
