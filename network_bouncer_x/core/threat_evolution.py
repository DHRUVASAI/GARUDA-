STAGE_LABELS = {1: 'Normal', 2: 'Exploration', 3: 'Scanning', 4: 'Probable Compromise'}


def classify_threat_level(dest_dev: float, port_dev: float, burst_dev: float,
                           new_peer_ratio: float, scan_score: float,
                           persistence: int, scan_dna: str,
                           thresholds: dict) -> int:
    """
    Rule-based stage classification.
    Thresholds are dataset-derived (from baseline.learn_deviation_thresholds).

    Level 1 — Normal
    Level 2 — Exploration  : 1 indicator mildly breached
    Level 3 — Scanning     : 2+ indicators breached
    Level 4 — Compromise   : Level 3 + (high score OR persistence OR Hybrid)
    """
    explore_t = thresholds.get('exploration', 2.0)
    scan_t    = thresholds.get('scanning',    4.0)

    # Count breached indicators
    breaches = sum([
        dest_dev       > explore_t,
        port_dev       > explore_t,
        burst_dev      > explore_t,
        new_peer_ratio > 0.30,
    ])
    strong_breaches = sum([
        dest_dev       > scan_t,
        port_dev       > scan_t,
        burst_dev      > scan_t,
        new_peer_ratio > 0.50,
    ])

    if strong_breaches >= 2 and (scan_score >= 75 or persistence >= 3 or scan_dna == 'Hybrid'):
        return 4
    if strong_breaches >= 2 or (breaches >= 2 and scan_score >= 40):
        return 3
    if breaches >= 1:
        return 2
    return 1


def apply_threat_evolution(window_records: list, thresholds: dict) -> list:
    """Apply threat level classification to every window record."""
    result = []
    for rec in window_records:
        level = classify_threat_level(
            rec.get('dest_dev', 1),
            rec.get('port_dev', 1),
            rec.get('burst_dev', 1),
            rec.get('new_peer_ratio', 0),
            rec.get('scan_score', 0),
            rec.get('persistence', 0),
            rec.get('scan_dna', 'Normal'),
            thresholds
        )
        result.append({**rec,
                       'threat_level':      level,
                       'threat_stage_label': STAGE_LABELS[level]})
    return result
