import numpy as np
import pandas as pd
from collections import defaultdict


# ── 1. Alert Triage Engine ────────────────────────────────────────────────────

def triage_score(rec: dict) -> float:
    """
    Composite triage score = Risk Score * Confidence weight * Persistence bonus.
    Used to rank alerts so SOC investigates most likely real attacks first.
    High score + high confidence + persistence = top of queue.
    """
    score      = rec.get('scan_score',   0) or 0
    conf       = rec.get('confidence',   0) or 0
    pers       = rec.get('persistence',  0) or 0
    votes      = rec.get('detector_votes', 0) or 0
    conf_w     = conf / 100.0
    pers_bonus = min(pers * 0.05, 0.25)        # max +25% from persistence
    vote_bonus = min(votes * 0.03, 0.15)       # max +15% from detector agreement
    return round(score * (conf_w + pers_bonus + vote_bonus), 2)


def build_triage_queue(window_records: list, top_n: int = 20) -> list:
    """
    Rank ALL alert-level records by triage score.
    Returns top_n deduplicated hosts with their worst window.
    One entry per host — the window with the highest triage score.
    """
    host_best = {}
    for rec in window_records:
        if not rec.get('is_alert'):
            continue
        src = rec['srcip']
        ts  = triage_score(rec)
        if src not in host_best or ts > host_best[src]['triage_score']:
            host_best[src] = {**rec, 'triage_score': ts}

    ranked = sorted(host_best.values(), key=lambda r: r['triage_score'], reverse=True)
    return ranked[:top_n]


# ── 2. Evidence Summary ───────────────────────────────────────────────────────

def build_evidence_summary(rec: dict, baselines: dict) -> dict:
    """
    Generate a SOC-ready evidence card for one host window.
    Format: +700% destination growth, Persistent 4 windows, etc.
    """
    src    = rec.get('srcip', '')
    b      = baselines.get(src, {})

    def _pct(dev): return f"+{(dev-1)*100:.0f}%" if dev > 1 else f"{(dev-1)*100:.0f}%"

    dd   = rec.get('dest_dev',  1) or 1
    pd_  = rec.get('port_dev',  1) or 1
    bd   = rec.get('burst_dev', 1) or 1
    pers = rec.get('persistence', 0) or 0
    dna  = rec.get('scan_dna', 'Normal')
    sim  = rec.get('similar_pattern', 'Unknown')
    sim_pct = rec.get('similarity_pct', 0) or 0
    npr  = rec.get('new_peer_ratio', 0) or 0
    votes = rec.get('detector_votes', 0) or 0

    lines = []
    if dd  > 1.2: lines.append(f"{_pct(dd)} destination growth ({dd:.1f}x baseline)")
    if pd_ > 1.2: lines.append(f"{_pct(pd_)} port diversity ({pd_:.1f}x baseline)")
    if bd  > 1.2: lines.append(f"{_pct(bd)} connection burst ({bd:.1f}x baseline)")
    if pers > 0:  lines.append(f"Persistent for {pers} consecutive anomalous windows")
    if dna != 'Normal': lines.append(f"{dna} Scan Pattern detected")
    if sim_pct > 50:    lines.append(f"{sim_pct:.0f}% similarity to {sim} attack pattern")
    if npr > 0.3:       lines.append(f"{npr:.0%} new peers — {rec.get('new_peer_count',0)} unseen hosts contacted")
    if votes >= 3:      lines.append(f"{votes}/5 independent detectors agree")

    return {
        'host':          src,
        'triage_score':  triage_score(rec),
        'scan_score':    rec.get('scan_score', 0),
        'confidence':    rec.get('confidence', 0),
        'severity':      rec.get('severity', 'Low'),
        'evidence_lines': lines,
        'scan_dna':      dna,
        'threat_stage':  rec.get('threat_stage_label', 'Normal'),
        'similar_to':    f"{sim} ({sim_pct:.0f}%)",
    }


# ── 3. Alert Suppression Justification ───────────────────────────────────────

def suppression_justification(rec: dict, bands: dict) -> dict:
    """
    For non-alert windows explain exactly WHY the alert was suppressed.
    This is the transparency layer that reduces analyst noise fatigue.
    """
    if rec.get('is_alert'):
        return {'suppressed': False, 'reasons': []}

    reasons = []
    score    = rec.get('scan_score',   0) or 0
    pers     = rec.get('persistence',  0) or 0
    conf     = rec.get('confidence',   0) or 0
    votes    = rec.get('detector_votes', 0) or 0
    dd       = rec.get('dest_dev',  1) or 1
    pd_      = rec.get('port_dev',  1) or 1
    bd       = rec.get('burst_dev', 1) or 1

    if dd > 2  and pd_ <= 2: reasons.append("Destination spike present but no Port anomaly")
    if bd > 2  and pd_ <= 2: reasons.append("Burst spike present but no Port anomaly")
    if dd > 2  and bd  <= 2: reasons.append("Destination spike present but no Burst anomaly")
    if pers < 2:             reasons.append(f"Only {pers} anomalous window(s) — persistence gate requires 2+")
    if conf < 40:            reasons.append(f"Confidence too low ({conf:.0f}%) — indicators not in agreement")
    if votes < 2:            reasons.append(f"Only {votes}/5 detectors fired — ensemble requires 2+")
    if score < bands.get('high', 75):
        reasons.append(f"Score {score:.0f} below critical threshold ({bands.get('high',75):.0f})")

    if not reasons:
        reasons.append("Marginal deviations — below all alert thresholds")

    return {'suppressed': True, 'score': score, 'reasons': reasons}


def build_suppression_log(window_records: list, bands: dict) -> list:
    """Build suppression log for all non-alert windows that had any deviation."""
    log = []
    for rec in window_records:
        if rec.get('is_alert'):
            continue
        # Only log windows with some anomaly signal
        if (rec.get('dest_dev', 1) > 1.5 or rec.get('port_dev', 1) > 1.5 or
                rec.get('burst_dev', 1) > 1.5):
            j = suppression_justification(rec, bands)
            log.append({
                'srcip':    rec['srcip'],
                'window':   rec['window'],
                'score':    rec.get('scan_score', 0),
                'reasons':  ' | '.join(j['reasons']),
            })
    return log


# ── 4. Investigation Path ─────────────────────────────────────────────────────

_INVESTIGATION_RULES = [
    # (condition_fn, likely_cause, evidence_list)
    (
        lambda r: r.get('scan_dna') == 'Hybrid' or
                  (r.get('dest_dev', 1) > 4 and r.get('port_dev', 1) > 4),
        'Full Subnet Reconnaissance',
        ['Contacting many new hosts', 'High port diversity across targets',
         'Typical pre-exploitation mapping behavior']
    ),
    (
        lambda r: r.get('scan_dna') == 'Horizontal',
        'Service Sweep / Lateral Movement Probe',
        ['Same port targeted across many hosts', 'Consistent with automated scanning tools',
         'Check for credential stuffing or exploit delivery']
    ),
    (
        lambda r: r.get('scan_dna') == 'Vertical',
        'Single Target Enumeration',
        ['Many ports probed on one host', 'Consistent with nmap full-port scan',
         'Attacker likely identified a target and is mapping its services']
    ),
    (
        lambda r: r.get('burst_dev', 1) > 5 and r.get('dest_dev', 1) <= 2,
        'Automated Script / Tool Activity',
        ['Very high connection rate with normal destination count',
         'Consistent with scripted scanning or brute-force activity',
         'Check host process list for automated tools']
    ),
    (
        lambda r: r.get('new_peer_ratio', 0) > 0.6,
        'Lateral Movement / Propagation',
        ['Majority of contacted hosts are new peers',
         'Host is reaching out to previously unknown machines',
         'Check for credential reuse or exploit propagation']
    ),
    (
        lambda r: r.get('dest_dev', 1) > 3,
        'Reconnaissance Activity',
        ['Destination spread significantly above baseline',
         'Host is communicating with unusually many targets',
         'Review ARP/DNS logs for subnet mapping']
    ),
]


def investigation_path(rec: dict) -> dict:
    """
    Determine likely cause and supporting evidence from observed behavior.
    Returns the first matching rule — ordered from most to least specific.
    """
    for condition, cause, evidence in _INVESTIGATION_RULES:
        try:
            if condition(rec):
                return {'likely_cause': cause, 'supporting_evidence': evidence}
        except Exception:
            continue
    return {
        'likely_cause': 'Marginal Anomaly',
        'supporting_evidence': ['Deviations present but below strong indicator thresholds',
                                 'Continue monitoring for escalation']
    }


# ── 5. Peer Comparison ────────────────────────────────────────────────────────

def peer_comparison(rec: dict, baselines: dict, pg_baselines: dict,
                    host_to_group: dict) -> dict:
    """
    Compare current host metrics against its peer group median.
    Makes clear whether a host is anomalous within its behavioral cluster.
    """
    src    = rec['srcip']
    pg_key = host_to_group.get(src)
    pg     = pg_baselines.get(pg_key, {}) if pg_key else {}

    metrics = {}
    for field, label, pg_key_inner in [
        ('unique_dsts',  'Destinations', 'dest'),
        ('unique_ports', 'Ports',        'ports'),
        ('conn_count',   'Connections',  'conns'),
    ]:
        current  = rec.get(field, 0)
        peer_med = pg.get(pg_key_inner, 1.0)
        ratio    = current / max(peer_med, 1)
        if ratio > 1.5:
            verdict = 'SUSPICIOUS vs peers'
        elif ratio < 0.5:
            verdict = 'Below peers (normal)'
        else:
            verdict = 'Normal vs peers'
        metrics[label] = {
            'current':  round(current, 1),
            'peer_avg': round(peer_med, 1),
            'ratio':    round(ratio, 2),
            'verdict':  verdict,
        }

    return {'peer_group': pg_key or 'Unknown', 'metrics': metrics}


# ── 6. Confidence Breakdown ───────────────────────────────────────────────────

def confidence_breakdown(rec: dict) -> dict:
    """
    Explain WHY confidence is high or low.
    Labels each indicator as Strong / Moderate / Weak / None.
    """
    def _label(score_0_1):
        if score_0_1 >= 0.7: return 'Strong'
        if score_0_1 >= 0.4: return 'Moderate'
        if score_0_1 >= 0.1: return 'Weak'
        return 'None'

    dd   = rec.get('dest_dev',  1) or 1
    pd_  = rec.get('port_dev',  1) or 1
    bd   = rec.get('burst_dev', 1) or 1
    npr  = rec.get('new_peer_ratio', 0) or 0
    lvl  = rec.get('threat_level', 1) or 1

    contributors = {
        'Destination Spread': _label(min(dd  / 10.0, 1.0)),
        'Port Diversity':     _label(min(pd_ / 10.0, 1.0)),
        'Burst Pattern':      _label(min(bd  / 10.0, 1.0)),
        'Peer Deviation':     _label(min(npr,         1.0)),
        'Threat Stage':       _label((lvl - 1) / 3.0),
    }
    strong_count = sum(1 for v in contributors.values() if v == 'Strong')
    return {
        'overall':      rec.get('confidence', 0),
        'contributors': contributors,
        'strong_count': strong_count,
        'interpretation': (
            'High confidence — multiple strong indicators agree' if strong_count >= 3 else
            'Medium confidence — some indicators present'        if strong_count >= 1 else
            'Low confidence — weak or single indicator only'
        )
    }


# ── Full SOC enrichment pass ──────────────────────────────────────────────────

def enrich_soc_features(window_records: list, baselines: dict,
                         pg_baselines: dict, host_to_group: dict,
                         bands: dict) -> tuple:
    """
    Attach all SOC features to every window record.
    Returns (enriched_records, triage_queue, suppression_log).
    """
    enriched = []
    for rec in window_records:
        enriched.append({
            **rec,
            'evidence_summary':   build_evidence_summary(rec, baselines),
            'investigation_path': investigation_path(rec),
            'peer_comparison':    peer_comparison(rec, baselines, pg_baselines, host_to_group),
            'confidence_breakdown': confidence_breakdown(rec),
        })

    triage_queue   = build_triage_queue(enriched)
    suppression_log = build_suppression_log(enriched, bands)

    return enriched, triage_queue, suppression_log
