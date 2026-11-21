"""GARUDA v5 Externalized Rule & Signature Manifest Loader.
Allows threat thresholds, OS port/TTL signatures, and campus heuristics to evolve
via versioned JSON manifests without modifying core scanner code.
"""

import json
from pathlib import Path
from typing import Any, Dict

RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "garuda_rules_v5.json"

_DEFAULT_RULES: Dict[str, Any] = {
    "schema_version": "5.0.0-fallback",
    "updated_at": "2026-11-21T00:00:00Z",
    "dga_entropy_threshold": 3.5,
    "beacon_cv_threshold": 0.15,
    "max_active_sweep_prefix": 24,
    "max_active_sweep_hosts": 254,
    "proxy_arp_min_shared_ips": 3,
    "campus_ssid_hints": ["campus", "university", "eduroam", "klu", "guest", "enterprise"],
    "port_os_signatures": {
        "62078": {"os": "Apple iOS (iPhone / iPad)", "device_type": "phone"},
        "445": {"os": "Windows PC (SMB)", "device_type": "laptop"},
        "5555": {"os": "Android Device (ADB)", "device_type": "phone"},
        "22": {"os": "Linux / Unix Host (SSH)", "device_type": "laptop"},
    },
    "ttl_os_profiles": {
        "64": "Linux / Android / iOS / macOS",
        "128": "Windows",
        "255": "Network Router / Appliance",
    },
    "vpc_suspicious_ports": [22, 23, 3389, 4444, 5555, 6667, 1337, 31337],
}


class RuleManifestManager:
    def __init__(self, path: Path = RULES_PATH):
        self.path = path
        self._rules: Dict[str, Any] = dict(_DEFAULT_RULES)
        self.reload()

    def reload(self) -> Dict[str, Any]:
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and "schema_version" in loaded:
                    merged = dict(_DEFAULT_RULES)
                    merged.update(loaded)
                    self._rules = merged
            except Exception:
                pass
        return self._rules

    @property
    def rules(self) -> Dict[str, Any]:
        return self._rules

    def summary(self) -> Dict[str, Any]:
        return {
            "schema_version": self._rules.get("schema_version"),
            "updated_at": self._rules.get("updated_at"),
            "path": str(self.path),
            "port_signatures_count": len(self._rules.get("port_os_signatures", {})),
            "campus_hints_count": len(self._rules.get("campus_ssid_hints", [])),
            "max_active_sweep_prefix": self._rules.get("max_active_sweep_prefix", 24),
            "proxy_arp_min_shared_ips": self._rules.get("proxy_arp_min_shared_ips", 3),
        }


rule_manager = RuleManifestManager()
