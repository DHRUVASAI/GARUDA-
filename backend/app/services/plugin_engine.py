"""GARUDA v5 Self-Isolating Discovery & Enrichment Plugin Orchestrator.
Each protocol adapter runs in an isolated worker with its own timeout budget so blocked
campus protocols (mDNS/SSDP/NetBIOS) never stall or crash the core engine.
"""

import concurrent.futures
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class PluginResult:
    name: str
    status: str  # ok | timeout | error | skipped
    elapsed_ms: float
    data: Any = None
    error: str = ""


@dataclass
class DiscoveryPlugin:
    name: str
    fn: Callable[[], Any]
    timeout_sec: float = 1.5
    enabled: bool = True


class PluginOrchestrator:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.last_run_report: List[Dict[str, Any]] = []

    def run_all(self, plugins: List[DiscoveryPlugin]) -> Dict[str, PluginResult]:
        results: Dict[str, PluginResult] = {}
        active = []
        for p in plugins:
            if not p.enabled:
                results[p.name] = PluginResult(name=p.name, status="skipped", elapsed_ms=0.0, data={})
            else:
                active.append(p)

        if not active:
            self.last_run_report = [r.__dict__ for r in results.values()]
            return results

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(active)))
        try:
            future_pairs = []
            starts = {}
            for p in active:
                starts[p.name] = time.perf_counter()
                future_pairs.append((p, pool.submit(p.fn)))

            for p, fut in future_pairs:
                try:
                    val = fut.result(timeout=p.timeout_sec)
                    elapsed = round((time.perf_counter() - starts[p.name]) * 1000.0, 2)
                    results[p.name] = PluginResult(name=p.name, status="ok", elapsed_ms=elapsed, data=val)
                except concurrent.futures.TimeoutError:
                    elapsed = round((time.perf_counter() - starts[p.name]) * 1000.0, 2)
                    fut.cancel()
                    results[p.name] = PluginResult(
                        name=p.name, status="timeout", elapsed_ms=elapsed, data={}, error=f"Exceeded {p.timeout_sec}s budget"
                    )
                except Exception as exc:
                    elapsed = round((time.perf_counter() - starts[p.name]) * 1000.0, 2)
                    results[p.name] = PluginResult(
                        name=p.name, status="error", elapsed_ms=elapsed, data={}, error=str(exc)
                    )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        self.last_run_report = [
            {"name": r.name, "status": r.status, "elapsed_ms": r.elapsed_ms, "error": r.error}
            for r in results.values()
        ]
        return results


plugin_orchestrator = PluginOrchestrator()
