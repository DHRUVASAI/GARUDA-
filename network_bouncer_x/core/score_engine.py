import numpy as np


# ── ScanScore ────────────────────────────────────────────────────────────────

def compute_scan_score(dest_dev: float, port_dev: float,
                       burst_dev: float, new_peer_ratio: float,
                       weights: dict) -> float:
    """
    Compute 0-100 risk score using dataset-learned weights.
    Each deviation is capped at 10x to prevent single-metric domination.
    """
    components = {
        'dest':  min(dest_dev  / 10.0, 1.0) * weights.get('dest',  0.40),
        'port':  min(port_dev  / 10.0, 1.0) * weights.get('port',  0.30),
        'burst': min(burst_dev / 10.0, 1.0) * weights.get('burst', 0.20),
        'peer':  min(new_peer_ratio,    1.0) * weights.get('peer',  0.10),
    }
    total_weight = sum(weights.get(k, 0) for k in ['dest', 'port', 'burst', 'peer'])
    raw = sum(components.values()) / max(total_weight, 1)
    return round(raw * 100, 2), components


# ── Confidence Score ─────────────────────────────────────────────────────────

def compute_confidence(dest_dev: float, port_dev: float, burst_dev: float,
                       new_peer_ratio: float, threat_level: int) -> float:
    """
    Indicator-agreement confidence score.
    Each indicator contributes proportionally to how much it deviates.
    All indicators must agree for high confidence — no black box.
    """
    w = {'dest': 0.35, 'port': 0.25, 'burst': 0.20, 'peer': 0.15, 'stage': 0.05}
    scores = {
        'dest':  min(dest_dev  / 10.0, 1.0),
        'port':  min(port_dev  / 10.0, 1.0),
        'burst': min(burst_dev / 10.0, 1.0),
        'peer':  min(new_peer_ratio,   1.0),
        'stage': threat_level / 4.0,
    }
    total_w    = sum(w.values())
    weighted   = sum(w[k] * scores[k] for k in w)
    return round((weighted / total_w) * 100, 1)


# ── Severity Classification ──────────────────────────────────────────────────

def classify_severity(score: float, bands: dict) -> str:
    """
    Map scan score to severity tier using dataset-learned bands.
    bands = {'low': X, 'medium': Y, 'high': Z}
    """
    if score >= bands.get('high', 75):
        return 'Critical'
    if score >= bands.get('medium', 55):
        return 'High'
    if score >= bands.get('low', 30):
        return 'Medium'
    return 'Low'


# ── Risk Stability ───────────────────────────────────────────────────────────

def compute_risk_stability(window_records: list) -> list:
    """
    Compute risk stability per host — measures how consistently elevated
    the risk score is across windows, not just the peak.

    Stability = (windows_above_threshold / total_windows) * 100
    Also computes score variance: low variance + high score = sustained threat.

    Adds: risk_stability_pct, score_variance, stability_label
    """
    from collections import defaultdict
    host_scores = defaultdict(list)
    for rec in window_records:
        host_scores[rec['srcip']].append(rec.get('scan_score', 0))

    stability_map = {}
    for src, scores in host_scores.items():
        arr       = np.array([s for s in scores if s == s], dtype=float)  # drop NaN
        if len(arr) == 0:
            stability_map[src] = {'risk_stability_pct': 0.0, 'score_variance': 0.0,
                                   'stability_label': 'Unknown'}
            continue
        threshold = np.percentile(arr, 50) if len(arr) > 1 else arr[0]
        above     = np.sum(arr > threshold)
        stab_pct  = round(float(above / len(arr)) * 100, 1)
        variance  = round(float(np.var(arr)), 2)

        if stab_pct >= 75 and variance < 100:
            label = 'Sustained'
        elif stab_pct >= 50:
            label = 'Recurring'
        elif stab_pct >= 25:
            label = 'Intermittent'
        else:
            label = 'Transient'

        stability_map[src] = {'risk_stability_pct': stab_pct,
                               'score_variance':     variance,
                               'stability_label':    label}

    return [{**rec,
             'risk_stability_pct': stability_map.get(rec['srcip'], {}).get('risk_stability_pct', 0),
             'score_variance':     stability_map.get(rec['srcip'], {}).get('score_variance', 0),
             'stability_label':    stability_map.get(rec['srcip'], {}).get('stability_label', 'Unknown')}
            for rec in window_records]



def apply_fp_guard(window_records: list, bands: dict, weights: dict) -> list:
    """
    Two-gate model:
      Gate 1 — Spike Gate:    score computed but not alerted
      Gate 2 — Persistence:   alert only if persistence >= 2
                               OR score >= Critical threshold (immediate)

    Adds fields: scan_score, score_components, confidence,
                 severity, is_alert, fp_guard_reason
    """
    critical_threshold = bands.get('high', 75)
    result = []

    for rec in window_records:
        score, components = compute_scan_score(
            rec.get('dest_dev', 1), rec.get('port_dev', 1),
            rec.get('burst_dev', 1), rec.get('new_peer_ratio', 0),
            weights
        )
        threat_level = rec.get('threat_level', 1)
        confidence   = compute_confidence(
            rec.get('dest_dev', 1), rec.get('port_dev', 1),
            rec.get('burst_dev', 1), rec.get('new_peer_ratio', 0),
            threat_level
        )
        severity = classify_severity(score, bands)
        persistence = rec.get('persistence', 0)

        # Gate logic
        if score >= critical_threshold:
            is_alert = True
            reason   = "Critical threshold override"
        elif persistence >= 2:
            is_alert = True
            reason   = f"Confirmed — {persistence} consecutive anomalous windows"
        else:
            is_alert = False
            reason   = "Single window spike — monitoring"

        result.append({**rec,
                       'scan_score':       score,
                       'score_components': components,
                       'confidence':       confidence,
                       'severity':         severity,
                       'is_alert':         is_alert,
                       'fp_guard_reason':  reason})
    return result
