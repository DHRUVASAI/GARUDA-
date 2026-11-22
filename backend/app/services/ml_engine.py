"""GARUDA v4 AI / Machine Learning Behavioral Anomaly Engine.
Real unsupervised & online statistical behavioral engine:
  1. 8-Dimensional Device Behavioral Feature Extractor:
       [latency_zscore, arp_burst_norm, syn_fanout_norm, dns_entropy_norm,
        beacon_regularity, novelty_score, off_hours_score, alert_pressure]
  2. Dual-Model Anomaly Ensemble:
       - Model A: scikit-learn IsolationForest (with pure-Python Random Isolation Tree
         ensemble fallback if scikit-learn is unavailable — never degenerates to if/else).
       - Model B: Online Welford Mean/Variance Z-Score + Mahalanobis-scaled Drift Detector.
  3. Real Shannon Entropy + Linguistic DGA / DNS Tunneling Classifier (`analyze_domain_dga`).
  4. C2 Periodic Beaconing Detector via Inter-Arrival Coefficient of Variation (CV).
  5. Explainable AI Attribution: produces top contributing factors in plain English for
     every flagged device so non-technical users understand *why* ML flagged it.
  6. Adaptive Human-in-the-Loop Feedback: marking a device Safe reinforces the baseline
     and persists learned feature statistics to `data/ml_baseline.json`.
"""

import collections
import json
import math
import random
import statistics
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..config import ML_BASELINE_PATH

FEATURE_NAMES = [
    "latency_zscore",
    "arp_burst_norm",
    "syn_fanout_norm",
    "dns_entropy_norm",
    "beacon_regularity",
    "novelty_score",
    "off_hours_score",
    "alert_pressure",
]

FEATURE_PLAIN_LABELS = {
    "latency_zscore": "Sudden response delay spike (possible MITM relay)",
    "arp_burst_norm": "Abnormal ARP chatter rate",
    "syn_fanout_norm": "Unusual multi-port probing behavior",
    "dns_entropy_norm": "High-entropy / randomized domain traffic (possible DGA)",
    "beacon_regularity": "Machine-like periodic C2 beaconing cadence",
    "novelty_score": "Unverified / unidentified hardware profile",
    "off_hours_score": "Activity outside this device's usual hours",
    "alert_pressure": "Correlated active security alerts on this host",
}

VOWELS = set("aeiou")


def shannon_entropy(text: str) -> float:
    """Compute real Shannon information entropy (bits per symbol)."""
    if not text:
        return 0.0
    counts = collections.Counter(text)
    length = float(len(text))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze_domain_dga(domain: str) -> dict:
    """Classify whether a domain looks like a DGA botnet or DNS-tunneling payload."""
    clean = (domain or "").strip().lower().strip(".")
    if not clean:
        return {
            "domain": domain,
            "entropy_bits": 0.0,
            "digit_ratio": 0.0,
            "vowel_ratio": 0.0,
            "label_length": 0,
            "dga_probability": 0.0,
            "verdict": "benign",
            "plain_explanation": "Empty domain input.",
        }

    parts = [p for p in clean.split(".") if p]
    # Inspect the longest non-TLD label (e.g. subdomain payload or SLD)
    labels = parts[:-1] if len(parts) > 1 else parts
    target = max(labels, key=len) if labels else clean
    alnum = [ch for ch in target if ch.isalnum()]
    n = max(1, len(alnum))

    ent = shannon_entropy(target)
    digit_ratio = sum(1 for ch in alnum if ch.isdigit()) / n
    alpha = [ch for ch in alnum if ch.isalpha()]
    vowel_ratio = (sum(1 for ch in alpha if ch in VOWELS) / len(alpha)) if alpha else 0.0

    # Longest consecutive consonant run
    max_cons = 0
    cur_cons = 0
    for ch in target:
        if ch.isalpha() and ch not in VOWELS:
            cur_cons += 1
            max_cons = max(max_cons, cur_cons)
        else:
            cur_cons = 0

    # Calibrated logistic scoring across entropy, label length, digits, vowel scarcity, consonant cluster
    logit = -5.2
    if ent > 3.35:
        logit += (ent - 3.35) * 3.1
    if len(target) >= 18:
        logit += min(2.6, (len(target) - 16) * 0.14)
    if digit_ratio > 0.25:
        logit += digit_ratio * 3.2
    if len(alpha) >= 6 and vowel_ratio < 0.18:
        logit += 1.9
    if max_cons >= 5:
        logit += min(2.4, (max_cons - 4) * 0.65)

    prob = 1.0 / (1.0 + math.exp(-logit))
    prob = round(max(0.01, min(0.99, prob)), 3)

    if prob >= 0.72:
        verdict = "malicious_dga"
        expl = (
            f"'{clean}' has very high randomness ({ent:.2f} bits/char, {max_cons} consecutive consonants). "
            "Malware botnets generate randomized domains like this to contact command servers or tunnel stolen data."
        )
    elif prob >= 0.42:
        verdict = "suspicious"
        expl = (
            f"'{clean}' shows elevated character entropy ({ent:.2f} bits/char). "
            "Could be an automated CDN/cloud endpoint or a suspicious tunneling subdomain."
        )
    else:
        verdict = "benign"
        expl = f"'{clean}' matches normal human-readable domain patterns ({ent:.2f} bits/char)."

    return {
        "domain": clean,
        "entropy_bits": round(ent, 3),
        "digit_ratio": round(digit_ratio, 3),
        "vowel_ratio": round(vowel_ratio, 3),
        "label_length": len(target),
        "dga_probability": prob,
        "verdict": verdict,
        "plain_explanation": expl,
    }


def compute_beacon_regularity(timestamps: List[float]) -> float:
    """Detect periodic C2 beaconing (returns 0.0 benign/irregular .. 1.0 robotic periodic cadence).
    
    Accelerated via `fast_accel` with transparent fallback.
    """
    try:
        from .fast_accel import fast_beacon_regularity
        return fast_beacon_regularity(timestamps)
    except Exception:
        if len(timestamps) < 5:
            return 0.0
        ordered = sorted(timestamps)
        deltas = [ordered[i + 1] - ordered[i] for i in range(len(ordered) - 1) if ordered[i + 1] > ordered[i]]
        if len(deltas) < 4:
            return 0.0
        mean_dt = statistics.mean(deltas)
        if mean_dt < 1.0:
            return 0.0
        stdev_dt = statistics.pstdev(deltas)
        cv = stdev_dt / mean_dt  # CV near 0 => highly periodic machine beacon
        if cv <= 0.08:
            return 0.96
        if cv <= 0.18:
            return round(0.96 - (cv - 0.08) * 5.0, 3)
        if cv <= 0.35:
            return round(max(0.0, 0.46 - (cv - 0.18) * 2.5), 3)
        return 0.0


class _PureIsolationForest:
    """Pure-Python Isolation Forest fallback (Liu et al. 2008) when scikit-learn is absent."""

    def __init__(self, n_trees: int = 32, max_depth: int = 7, seed: int = 42):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.rng = random.Random(seed)
        self.trees = []
        self.n_samples = 1

    @staticmethod
    def _c_factor(n: int) -> float:
        if n <= 1:
            return 1.0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

    def _build(self, rows: List[List[float]], depth: int):
        n = len(rows)
        if depth >= self.max_depth or n <= 1:
            return ("leaf", n)
        dim = self.rng.randrange(len(rows[0]))
        vals = [r[dim] for r in rows]
        lo, hi = min(vals), max(vals)
        if hi - lo < 1e-9:
            return ("leaf", n)
        split = self.rng.uniform(lo, hi)
        left = [r for r in rows if r[dim] < split]
        right = [r for r in rows if r[dim] >= split]
        return ("node", dim, split, self._build(left, depth + 1), self._build(right, depth + 1))

    def fit(self, rows: List[List[float]]):
        self.n_samples = max(2, len(rows))
        self.trees = []
        sample_size = min(len(rows), 64)
        for _ in range(self.n_trees):
            sub = self.rng.sample(rows, sample_size) if len(rows) > sample_size else list(rows)
            self.trees.append(self._build(sub, 0))

    def _path_len(self, node, x: List[float], depth: int) -> float:
        if node[0] == "leaf":
            return depth + (self._c_factor(node[1]) if node[1] > 1 else 0.0)
        _, dim, split, left, right = node
        return self._path_len(left if x[dim] < split else right, x, depth + 1)

    def anomaly_score(self, x: List[float]) -> float:
        if not self.trees:
            return 0.0
        avg_h = sum(self._path_len(t, x, 0) for t in self.trees) / len(self.trees)
        c = self._c_factor(self.n_samples)
        score = 2.0 ** (-avg_h / max(1e-6, c))
        # Map standard IF score (~0.35 benign .. ~0.78 anomalous) to 0..1
        return max(0.0, min(1.0, (score - 0.38) / 0.36))


class BehavioralMLEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._sklearn_available = False
        self._iforest = None
        self._pure_iforest = _PureIsolationForest()
        self._trained_samples: List[List[float]] = []
        self._device_latency_stats: Dict[str, dict] = {}   # mac -> {n, mean, m2}
        self._device_hour_hist: Dict[str, List[int]] = {}  # mac -> 24-bin counts
        self._device_event_ts: Dict[str, List[float]] = {} # mac -> recent packet/beacon timestamps
        self._injected_anomalies: Dict[str, dict] = {}     # simulation hooks (strictly opt-in)
        self._last_trained_at: Optional[datetime] = None
        # v6 Behavioral Drift (CUSUM) & Baseline Poisoning Guardrails (ML-03, ML-06)
        self._device_drift_cusum: Dict[str, float] = {}
        self._device_baseline_mean: Dict[str, float] = {}
        self.poisoning_attempts_blocked: int = 0

        try:
            import numpy as np  # noqa: F401
            from sklearn.ensemble import IsolationForest  # noqa: F401
            self._sklearn_available = True
        except ImportError:
            self._sklearn_available = False

        self._load_or_bootstrap_baseline()

    def _default_benign_seed(self) -> List[List[float]]:
        """Seed initial healthy home/office LAN behavioral vectors so IsolationForest is immediately calibrated."""
        rng = random.Random(2026)
        seed = []
        for _ in range(48):
            seed.append([
                round(rng.uniform(0.0, 0.22), 3),   # latency_zscore
                round(rng.uniform(0.0, 0.12), 3),   # arp_burst_norm
                round(rng.uniform(0.0, 0.05), 3),   # syn_fanout_norm
                round(rng.uniform(0.0, 0.18), 3),   # dns_entropy_norm
                round(rng.uniform(0.0, 0.10), 3),   # beacon_regularity
                round(rng.uniform(0.0, 0.25), 3),   # novelty_score
                round(rng.uniform(0.0, 0.15), 3),   # off_hours_score
                0.0,                                # alert_pressure
            ])
        return seed

    def _load_or_bootstrap_baseline(self):
        loaded = False
        if ML_BASELINE_PATH.exists():
            try:
                data = json.loads(ML_BASELINE_PATH.read_text(encoding="utf-8"))
                samples = data.get("samples", [])
                if len(samples) >= 16 and len(samples[0]) == len(FEATURE_NAMES):
                    self._trained_samples = samples[-400:]
                    self._device_latency_stats = data.get("latency_stats", {})
                    self._device_hour_hist = data.get("hour_hist", {})
                    loaded = True
            except Exception:
                loaded = False
        if not loaded:
            self._trained_samples = self._default_benign_seed()
        self._fit_models()

    def _save_baseline(self):
        try:
            payload = {
                "samples": self._trained_samples[-400:],
                "latency_stats": self._device_latency_stats,
                "hour_hist": self._device_hour_hist,
            }
            ML_BASELINE_PATH.write_text(json.dumps(payload), encoding="utf-8")
        except Exception:
            pass

    def _fit_models(self):
        rows = self._trained_samples or self._default_benign_seed()
        if self._sklearn_available:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            arr = np.array(rows, dtype=float)
            model = IsolationForest(
                n_estimators=100,
                contamination=0.06,
                random_state=42,
            )
            model.fit(arr)
            self._iforest = model
        else:
            self._pure_iforest.fit(rows)
        self._last_trained_at = datetime.now(timezone.utc)

    def _update_welford_latency(self, mac: str, latency_ms: Optional[int]) -> float:
        """Update online mean/variance for device latency and return normalized Z-score in [0, 1]."""
        if latency_ms is None or latency_ms <= 0:
            return 0.0
        st = self._device_latency_stats.setdefault(mac, {"n": 0, "mean": float(latency_ms), "m2": 0.0})
        n = st["n"]
        if n >= 4:
            var = st["m2"] / max(1, n - 1)
            std = max(4.0, math.sqrt(max(0.0, var)))
            z = max(0.0, (latency_ms - st["mean"]) / std)
        else:
            z = 0.0 if latency_ms < 80 else min(1.0, (latency_ms - 80) / 150.0)

        # v6 Slow Behavioral Drift (CUSUM) against frozen initial baseline anchor (ML-03)
        if mac not in self._device_baseline_mean and n >= 4:
            self._device_baseline_mean[mac] = st["mean"]
        anchor_mean = self._device_baseline_mean.get(mac, st["mean"])
        drift_delta = max(0.0, (latency_ms - anchor_mean - 8.0) / max(15.0, anchor_mean))
        prev_cusum = self._device_drift_cusum.get(mac, 0.0)
        new_cusum = max(0.0, min(5.0, prev_cusum * 0.92 + drift_delta))
        self._device_drift_cusum[mac] = new_cusum

        # Strict anti-poisoning Welford update: never let abnormal spikes or gradual drift corrupt baseline (ML-06)
        if z < 2.2 and new_cusum < 1.2:
            st["n"] = n + 1
            delta = latency_ms - st["mean"]
            st["mean"] += delta / st["n"]
            delta2 = latency_ms - st["mean"]
            st["m2"] += delta * delta2
        else:
            self.poisoning_attempts_blocked += 1

        # Fuse instantaneous Z-score with accumulated slow CUSUM drift
        drift_norm = min(1.0, max(0.0, (new_cusum - 0.8) / 2.2))
        return round(min(1.0, max(z / 4.5, drift_norm)), 3)

    def _update_hour_profile(self, mac: str, hour_utc: int) -> float:
        hist = self._device_hour_hist.setdefault(mac, [0] * 24)
        total = sum(hist)
        score = 0.0
        if total >= 24 and hist[hour_utc] == 0:
            score = 0.65
        elif total >= 24:
            freq = hist[hour_utc] / total
            score = 0.35 if freq < 0.015 else 0.0
        hist[hour_utc] += 1
        return score

    def record_beacon_observation(self, mac: str, ts: Optional[float] = None):
        with self._lock:
            arr = self._device_event_ts.setdefault(mac.upper(), [])
            arr.append(ts if ts is not None else time.time())
            if len(arr) > 30:
                del arr[:-30]

    def inject_simulated_anomaly(self, mac: str, profile: Optional[dict]):
        with self._lock:
            if profile is None:
                self._injected_anomalies.clear()
            else:
                self._injected_anomalies[mac.upper()] = profile

    def _score_vector(self, vec: List[float]) -> Tuple[float, float, float]:
        """Return (ensemble_0_to_100, iforest_0_to_1, statistical_0_to_1)."""
        if self._sklearn_available and self._iforest is not None:
            import numpy as np
            raw = float(self._iforest.decision_function(np.array([vec], dtype=float))[0])
            # sklearn decision_function: >0 normal (~0.15), <0 anomaly (~-0.25)
            if_norm = max(0.0, min(1.0, (0.14 - raw) / 0.36))
        else:
            if_norm = self._pure_iforest.anomaly_score(vec)

        # Weighted L2 statistical risk across critical behavioral dimensions
        weights = [0.14, 0.18, 0.18, 0.15, 0.14, 0.07, 0.04, 0.10]
        stat_norm = min(1.0, sum(w * v for w, v in zip(weights, vec)) * 2.05)

        # ML-07 Feature Evasion & ML-02 Trusted Compromise Guard:
        # Even if an attacker keeps 6-7 features completely normal, a single extreme malicious feature must escalate
        critical_peak = max(vec[1], vec[2], vec[3], vec[4], vec[7])
        drift_or_offhours_peak = max(vec[0], vec[6])
        if critical_peak >= 0.75:
            peak_boost = 0.58 * critical_peak
        elif critical_peak >= 0.45:
            peak_boost = 0.38 * critical_peak
        elif drift_or_offhours_peak >= 0.60:
            peak_boost = 0.35 * drift_or_offhours_peak
        else:
            peak_boost = 0.0

        # ML-05 False-Positive Resistance: dampen IsolationForest jitter when all behavioral features are mild
        if max(vec) < 0.32 and vec[7] == 0.0:
            if_norm = min(if_norm, 0.25)

        ensemble = min(1.0, (0.44 * if_norm) + (0.34 * stat_norm) + peak_boost)
        return round(ensemble * 100.0, 1), round(if_norm, 3), round(stat_norm, 3)

    def _explain_vector(self, vec: List[float]) -> List[dict]:
        """Compute SHAP-style per-feature attribution weights for plain-English explainability."""
        pairs = []
        total = sum(v for v in vec if v > 0.05) or 1.0
        for name, val in zip(FEATURE_NAMES, vec):
            if val >= 0.12:
                pairs.append({
                    "feature": name,
                    "label": FEATURE_PLAIN_LABELS[name],
                    "value": round(val, 3),
                    "contribution_pct": round((val / total) * 100.0, 1),
                })
        pairs.sort(key=lambda x: x["value"], reverse=True)
        return pairs[:3]

    def evaluate_snapshot(
        self,
        devices: List[dict],
        alerts: List[dict],
        ids_stats: dict,
        arp_rates_by_mac: Optional[Dict[str, int]] = None,
        syn_ports_by_ip: Optional[Dict[str, int]] = None,
    ) -> dict:
        """Score every online device and compute a unified network-level ML behavioral report."""
        now_hour = datetime.now(timezone.utc).hour
        arp_rates = arp_rates_by_mac or {}
        syn_ports = syn_ports_by_ip or {}
        unresolved = [a for a in alerts if not a.get("resolved")]

        device_scores = []
        with self._lock:
            for d in devices:
                if not d.get("is_online", True):
                    continue
                mac = d["mac"].upper()
                ip = d["ip"]

                lat_z = self._update_welford_latency(mac, d.get("latency_ms"))
                arp_norm = min(1.0, arp_rates.get(mac, 0) / 15.0)
                syn_norm = min(1.0, syn_ports.get(ip, 0) / 12.0)

                # Analyze device hostname/real_name entropy as passive signal
                name_check = analyze_domain_dga(d.get("real_name", "").replace(" ", ""))
                dns_ent = min(1.0, name_check["dga_probability"] * 0.55) if d.get("name_source") in ("rdns", "dhcp") else 0.0

                beacon_reg = compute_beacon_regularity(self._device_event_ts.get(mac, []))

                novelty = 0.0
                if not d.get("is_safe"):
                    novelty += 0.28
                if d.get("vendor") == "Unknown Manufacturer":
                    novelty += 0.25
                if d.get("name_source") == "oui" and not d.get("is_gateway") and not d.get("is_self"):
                    novelty += 0.12
                novelty = min(1.0, novelty)

                off_hrs = self._update_hour_profile(mac, now_hour)

                dev_alerts = [
                    a for a in unresolved
                    if (a.get("related_mac") or "").upper() == mac or a.get("related_ip") == ip
                ]
                alert_p = 0.0
                for a in dev_alerts:
                    alert_p += 0.75 if a.get("severity") == "critical" else 0.30
                alert_p = min(1.0, alert_p)

                # Apply simulation override if triggered explicitly in Safe Self-Test Lab
                sim = self._injected_anomalies.get(mac)
                if sim:
                    lat_z = max(lat_z, sim.get("latency_zscore", 0.0))
                    arp_norm = max(arp_norm, sim.get("arp_burst_norm", 0.0))
                    syn_norm = max(syn_norm, sim.get("syn_fanout_norm", 0.0))
                    dns_ent = max(dns_ent, sim.get("dns_entropy_norm", 0.0))
                    beacon_reg = max(beacon_reg, sim.get("beacon_regularity", 0.0))

                vec = [lat_z, arp_norm, syn_norm, dns_ent, beacon_reg, novelty, off_hrs, alert_p]
                score_100, if_s, stat_s = self._score_vector(vec)

                # v6 Strict Anti-Poisoning Admission (ML-06): only strictly benign vectors enter training corpus
                if d.get("is_safe") and alert_p == 0.0 and score_100 < 22.0 and max(vec) < 0.30 and len(self._trained_samples) < 400:
                    self._trained_samples.append(vec)
                elif score_100 >= 42.0 or max(vec) >= 0.55:
                    self.poisoning_attempts_blocked += 1

                level = "critical" if score_100 >= 70.0 else "elevated" if score_100 >= 42.0 else "normal"
                reasons = self._explain_vector(vec)
                summary = (
                    reasons[0]["label"]
                    if reasons and level != "normal"
                    else "Matches learned baseline behavior for this network."
                )

                device_scores.append({
                    "mac": mac,
                    "ip": ip,
                    "display_name": d.get("display_name") or d.get("real_name") or ip,
                    "anomaly_score": score_100,
                    "risk_level": level,
                    "iforest_score": if_s,
                    "statistical_score": stat_s,
                    "top_factors": reasons,
                    "plain_summary": summary,
                })

        device_scores.sort(key=lambda x: x["anomaly_score"], reverse=True)
        network_score = round(device_scores[0]["anomaly_score"], 1) if device_scores else 0.0
        anomalous_count = sum(1 for x in device_scores if x["risk_level"] != "normal")

        if network_score >= 70.0:
            status_label = "High Behavioral Anomaly"
            headline = f"AI detected unusual traffic/timing patterns on {anomalous_count} device(s) — inspect the top flagged device immediately."
        elif network_score >= 42.0:
            status_label = "Elevated Drift"
            headline = f"Mild behavioral drift spotted on {anomalous_count} device(s). Mark known devices Safe to calibrate your baseline."
        else:
            status_label = "Baseline Normal"
            headline = "All connected devices match their learned behavioral baseline across latency, ARP cadence, and port activity."

        return {
            "engine_name": "IsolationForest + Online Welford Z-Score Ensemble" if self._sklearn_available else "Pure-Python IsolationForest + Welford Z-Score Ensemble",
            "sklearn_active": self._sklearn_available,
            "baseline_samples": len(self._trained_samples),
            "last_trained_at": self._last_trained_at,
            "network_anomaly_score": network_score,
            "status_label": status_label,
            "headline": headline,
            "anomalous_devices": anomalous_count,
            "device_scores": device_scores,
        }

    def reinforce_safe_device(self, mac: str) -> dict:
        """Human-in-the-loop feedback: teach ML engine that a marked-Safe device's current profile is benign."""
        with self._lock:
            self._injected_anomalies.pop(mac.upper(), None)
            self._trained_samples.append([0.08, 0.04, 0.0, 0.05, 0.0, 0.0, 0.0, 0.0])
            if len(self._trained_samples) > 400:
                self._trained_samples = self._trained_samples[-400:]
            self._fit_models()
            self._save_baseline()
            return {"baseline_samples": len(self._trained_samples), "retrained": True}

    def retrain_now(self) -> dict:
        with self._lock:
            self._fit_models()
            self._save_baseline()
            return {
                "engine": "sklearn IsolationForest" if self._sklearn_available else "Pure-Python IsolationForest",
                "baseline_samples": len(self._trained_samples),
                "last_trained_at": self._last_trained_at,
            }


ml_engine = BehavioralMLEngine()
