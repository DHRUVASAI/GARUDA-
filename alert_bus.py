"""
Thread-safe fan-out for Server-Sent Events (SSE) alert stream.
Used by garuda_backend (SSE route) and database.save_alert / monitor (broadcast).
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_clients: List[queue.Queue] = []


def register_client() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=32)
    with _lock:
        _clients.append(q)
    return q


def unregister_client(q: queue.Queue) -> None:
    with _lock:
        if q in _clients:
            _clients.remove(q)


def broadcast_alert(payload: Dict[str, Any]) -> None:
    """Non-blocking push to all SSE subscribers; drops if client queue is full."""
    data = json.dumps(payload, default=str)
    with _lock:
        targets = list(_clients)
    for q in targets:
        try:
            q.put_nowait(data)
        except queue.Full:
            logger.debug("SSE client queue full; dropping event")
        except Exception:
            logger.debug("SSE broadcast client error", exc_info=True)
