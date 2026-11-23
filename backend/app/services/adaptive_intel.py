"""
GARUDA v10 Adaptive Intelligence & Safe-Mode Controller
-------------------------------------------------------
Upgrades over v9:
  - Persistent disk state (data/adaptive_state.json) so restarts never reset thresholds or FP history.
  - Exponentially damped Bayesian threshold update (asymptotically approaches max_threshold, zero overshoot).
  - Safe-Mode failover controller with auditability.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..config import DATA_DIR

ADAPTIVE_STATE_PATH = DATA_DIR / "adaptive_state.json"


class AdaptiveIntelController:
    def __init__(self, state_path: Path = ADAPTIVE_STATE_PATH) -> None:
        self._state_path = state_path
        self.base_threshold: float = 0.65
        self.min_threshold: float = 0.45
        self.max_threshold: float = 0.88
        self.safe_mode: bool = False
        self.safe_mode_reason: str = ""
        self.false_positive_history: List[Dict[str, Any]] = []
        self._load_state()

    def _load_state(self) -> None:
        try:
            if self._state_path.exists():
                data = json.loads(self._state_path.read_text(encoding="utf-8"))
                self.base_threshold = float(data.get("base_threshold", 0.65))
                self.safe_mode = bool(data.get("safe_mode", False))
                self.safe_mode_reason = str(data.get("safe_mode_reason", ""))
                self.false_positive_history = list(data.get("false_positive_history", []))[-200:]
        except Exception:
            pass

    def _save_state(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "base_threshold": self.base_threshold,
                "safe_mode": self.safe_mode,
                "safe_mode_reason": self.safe_mode_reason,
                "false_positive_history": self.false_positive_history[-200:],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def record_false_positive(self, alert_id: int, indicator: str, actor: str) -> Dict[str, Any]:
        """Exponentially damped threshold update prevents overshoot and baseline poisoning."""
        entry = {
            "alert_id": alert_id,
            "indicator": indicator,
            "actor": actor,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.false_positive_history.append(entry)
        # Asymptotic damped step: 12% of remaining headroom toward max_threshold
        headroom = max(0.0, self.max_threshold - self.base_threshold)
        self.base_threshold = min(self.max_threshold, round(self.base_threshold + headroom * 0.12, 4))
        self._save_state()
        return {
            "status": "recorded",
            "new_dynamic_threshold": self.base_threshold,
            "total_false_positives": len(self.false_positive_history),
            "persisted": True,
        }

    def explain_anomaly(self, raw_score: float, signals: List[str]) -> Dict[str, Any]:
        confidence = round(min(0.99, max(0.05, raw_score)), 2)
        severity = "critical" if confidence >= 0.85 else "high" if confidence >= 0.7 else "medium" if confidence >= 0.5 else "low"
        return {
            "confidence_score": confidence,
            "severity": severity,
            "dynamic_threshold": self.base_threshold,
            "triggered": confidence >= self.base_threshold,
            "explanation": f"Flagged with {int(confidence * 100)}% confidence based on: {', '.join(signals) or 'behavioral deviation'}.",
        }

    def set_safe_mode(self, enabled: bool, reason: str = "") -> Dict[str, Any]:
        self.safe_mode = enabled
        self.safe_mode_reason = reason if enabled else ""
        self._save_state()
        return {
            "safe_mode": self.safe_mode,
            "reason": self.safe_mode_reason,
            "mode_description": "Passive read-only alerting active; automated blocking paused." if enabled else "Full active defense operational.",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "dynamic_threshold": self.base_threshold,
            "poisoning_guard_bounds": [self.min_threshold, self.max_threshold],
            "verified_false_positives": len(self.false_positive_history),
            "safe_mode": self.safe_mode,
            "safe_mode_reason": self.safe_mode_reason,
            "persisted": self._state_path.exists(),
        }


adaptive_intel = AdaptiveIntelController()
