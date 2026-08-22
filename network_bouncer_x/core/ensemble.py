import numpy as np


# ── 5 Independent Detectors ──────────────────────────────────────────────────

def _detect_destination(rec: dict, thresholds: dict) -> tuple:
    """Detector 1: Destination spread anomaly."""
    dev = rec.get('dest_dev', 1)
    fired = dev > thresholds.get('exploration', 2.0)
    reason = f"Dest spread {dev:.1f}x above combined baseline" if fired else None
    return fired, reason


def _detect_port(rec: dict, thresholds: dict) -> tuple:
    """Detector 2: Port diversity anomaly."""
    dev = rec.get('port_dev', 1)
    fired = dev > thresholds.get('exploration', 2.0)
    reason = f"Port diversity {dev:.1f}x above combined baseline" if fired else None
    return fired, reason


def _detect_burst(rec: dict, thresholds: dict) -> tuple:
    """Detector 3: Connection burst anomaly."""
    dev = rec.get('burst_dev', 1)
    fired = dev > thresholds.get('exploration', 2.0)
    reason = f"Connection burst {dev:.1f}x above combined baseline" if fired else None
    return fired, reason


def _detect_protocol(rec: dict, baselines: dict) -> tuple:
    """
    Detector 4: Protocol anomaly.
    Fires if dominant protocol in this window differs from the host's baseline protocol.
    Columns used: proto (via dominant_proto in window record)
    """
    src = rec.get('srcip', '')
    b = baselines.get(src, {})
    baseline_proto = b.get('top_proto', 'unknown')
    current_proto  = rec.get('dominant_proto', 'unknown')
    fired = (baseline_proto != 'unknown' and
             current_proto  != 'unknown' and
             current_proto  != baseline_proto)
    reason = (f"Protocol changed from baseline '{baseline_proto}' "
              f"to '{current_proto}'") if fired else None
    return fired, reason


def _detect_peer(rec: dict, thresholds: dict) -> tuple:
    """Detector 5: New peer ratio anomaly."""
    npr = rec.get('new_peer_ratio', 0)
    npc = rec.get('new_peer_count', 0)
    fired = npr > 0.30 and npc > 0
    reason = (f"{npr:.0%} new peers ({npc} hosts) not seen in baseline"
              ) if fired else None
    return fired, reason


# ── Ensemble Voting ──────────────────────────────────────────────────────────

def run_ensemble(window_records: list, thresholds: dict, baselines: dict) -> list:
    """
    Run all 5 detectors on every window record.
    Vote tally determines ensemble confidence:
      5/5 → Very High
      4/5 → High
      3/5 → Medium
      2/5 → Low
      1/5 → Marginal
      0/5 → Clean

    Adds: detector_votes, detector_reasons, ensemble_confidence, ensemble_fired
    """
    result = []
    for rec in window_records:
        detectors = [
            ('Destination', _detect_destination(rec, thresholds)),
            ('Port',        _detect_port(rec, thresholds)),
            ('Burst',       _detect_burst(rec, thresholds)),
            ('Protocol',    _detect_protocol(rec, baselines)),
            ('Peer',        _detect_peer(rec, thresholds)),
        ]

        votes   = sum(1 for _, (fired, _) in detectors if fired)
        reasons = [f"[{name}] {reason}"
                   for name, (fired, reason) in detectors if fired and reason]

        confidence_labels = {5: 'Very High', 4: 'High', 3: 'Medium',
                             2: 'Low', 1: 'Marginal', 0: 'Clean'}

        result.append({
            **rec,
            'detector_votes':       votes,
            'detector_reasons':     reasons,
            'ensemble_confidence':  confidence_labels[votes],
            'ensemble_fired':       votes >= 2,   # require 2+ detectors to agree
        })
    return result
