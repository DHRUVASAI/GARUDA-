import numpy as np
from collections import defaultdict


# ── Explainability ───────────────────────────────────────────────────────────

def explain_alert(rec: dict) -> list:
    """
    Generate human-readable reasons why a host was flagged.
    Every reason is directly tied to an observed metric.
    """
    reasons = []
    dd  = rec.get('dest_dev', 1)
    pd_ = rec.get('port_dev', 1)
    bd  = rec.get('burst_dev', 1)
    npr = rec.get('new_peer_ratio', 0)
    npc = rec.get('new_peer_count', 0)
    dna = rec.get('scan_dna', 'Normal')

    if dd > 2:
        reasons.append(f"Destination count is {dd:.1f}x above this host's normal baseline")
    if pd_ > 2:
        reasons.append(f"Port diversity is {pd_:.1f}x above this host's normal baseline")
    if bd > 2:
        reasons.append(f"Connection burst is {bd:.1f}x above normal rate")
    if npr > 0.3:
        reasons.append(f"{npr:.0%} of contacted hosts are previously unseen peers ({npc} new)")
    if dna != 'Normal':
        reasons.append(f"Scan pattern classified as {dna} — see Scan DNA panel")

    return reasons if reasons else ["Marginal deviation — no single strong indicator"]


# ── Recommendations ──────────────────────────────────────────────────────────

def generate_recommendations(rec: dict) -> list:
    """
    Evidence-mapped analyst recommendations.
    Each recommendation is triggered by specific observed behavior.
    """
    recs = []
    dd   = rec.get('dest_dev', 1)
    pd_  = rec.get('port_dev', 1)
    bd   = rec.get('burst_dev', 1)
    npr  = rec.get('new_peer_ratio', 0)
    dna  = rec.get('scan_dna', 'Normal')
    lvl  = rec.get('threat_level', 1)
    pers = rec.get('persistence', 0)

    if dd > 4:
        recs.append("Review ARP/DNS query logs — host may be mapping the internal subnet")
    if pd_ > 4:
        recs.append("Inspect host processes for enumeration tools (nmap, masscan, custom scripts)")
    if bd > 3:
        recs.append("Correlate with EDR process tree — look for scripted or automated scan launchers")
    if npr > 0.5:
        recs.append("Audit lateral movement — check auth logs (SMB/RDP/SSH) to newly contacted peers")
    if dna == 'Horizontal':
        recs.append("Block the swept port at the internal segment boundary; alert all targeted hosts")
    if dna == 'Vertical':
        recs.append("Isolate or firewall the target host — attacker is enumerating its open services")
    if dna == 'Hybrid':
        recs.append("ESCALATE IMMEDIATELY — full subnet reconnaissance in progress; engage IR team")
    if lvl == 4:
        recs.append("Initiate IR playbook — consider host isolation pending forensic investigation")
    if pers >= 3:
        recs.append("Activity is sustained across multiple windows — treat as ongoing, not a spike")

    return recs if recs else ["Continue monitoring — no immediate action required"]


# ── Historical Pattern Similarity ────────────────────────────────────────────

def build_attack_profiles(df) -> dict:
    """
    Build feature vectors for each known attack category using median stats.
    Columns used: label, attack_cat, srcip, dstip, dsport, dur
    """
    profiles = {}
    attack_df = df[df['label'] == 1]
    for cat, grp in attack_df.groupby('attack_cat'):
        profiles[cat] = np.array([
            grp.groupby('srcip')['dstip'].nunique().median(),
            grp.groupby('srcip')['dsport'].nunique().median(),
            grp.groupby('srcip').size().median(),
            0.5   # new_peer_ratio placeholder — computed in detection phase
        ], dtype=float)
    return profiles


def pattern_similarity(rec: dict, attack_profiles: dict) -> tuple:
    """
    Cosine similarity between current host window vector and known attack profiles.
    Returns (best_category, similarity_pct, second_best_category, second_pct).
    """
    if not attack_profiles:
        return 'Unknown', 0.0, 'Unknown', 0.0

    host_vec = np.array([
        rec.get('unique_dsts', 0),
        rec.get('unique_ports', 0),
        rec.get('conn_count', 0),
        rec.get('new_peer_ratio', 0)
    ], dtype=float)

    similarities = {}
    for cat, pvec in attack_profiles.items():
        norm = np.linalg.norm(host_vec) * np.linalg.norm(pvec)
        if norm == 0:
            similarities[cat] = 0.0
        else:
            similarities[cat] = float(np.dot(host_vec, pvec) / norm)

    sorted_sims = sorted(similarities.items(), key=lambda x: x[1], reverse=True)
    best   = sorted_sims[0]  if len(sorted_sims) > 0 else ('Unknown', 0.0)
    second = sorted_sims[1]  if len(sorted_sims) > 1 else ('Unknown', 0.0)
    return best[0], round(best[1]*100, 1), second[0], round(second[1]*100, 1)


# ── Multi-Baseline Explainability ───────────────────────────────────────────

def explain_multi_baseline(rec: dict) -> list:
    """
    Show how the host looks across all 3 baselines.
    Catches compromised-baseline hosts that look normal to themselves
    but abnormal to their peer group or globally.
    """
    lines = []
    for metric, label in [('dest', 'Destination'), ('port', 'Port'), ('burst', 'Burst')]:
        hd = rec.get(f'host_{metric}_dev')   # None if sparse history
        pd = rec.get(f'peer_{metric}_dev', 1)
        gd = rec.get(f'global_{metric}_dev', 1)
        if hd is not None:
            lines.append(f"{label}: vs Host={hd:.1f}x | vs Peer Group={pd:.1f}x | vs Global={gd:.1f}x")
        else:
            lines.append(f"{label}: vs Peer Group={pd:.1f}x | vs Global={gd:.1f}x (limited host history)")
    return lines


# ── Counterfactual Analysis ──────────────────────────────────────────────────

def counterfactual_analysis(rec: dict, baselines: dict) -> list:
    """
    Answer: What would this host need to look like to be considered normal?
    For each anomalous metric, state the normal value and the excess.
    """
    src = rec.get('srcip', '')
    b   = baselines.get(src, {})
    lines = []

    pairs = [
        ('unique_dsts',  'dest',  'Destination count'),
        ('unique_ports', 'ports', 'Port diversity'),
        ('conn_count',   'conns', 'Connection count'),
    ]
    for field, bkey, label in pairs:
        current  = rec.get(field, 0)
        normal   = b.get(bkey, {}).get('median', current) if b else current
        excess   = max(current - normal, 0)
        if excess > 0 and current > normal * 1.5:
            lines.append(
                f"{label}: current={current:.0f} | normal≈{normal:.0f} | "
                f"excess={excess:.0f} ({current/max(normal,1):.1f}x)"
            )
    return lines if lines else ["Behavior within normal range — no counterfactual needed"]


# ── Full enrichment pass ─────────────────────────────────────────────────────

def enrich_with_explainability(window_records: list, attack_profiles: dict,
                               baselines: dict = None) -> list:
    """Attach explanations, recommendations, pattern similarity, multi-baseline, and counterfactual."""
    result = []
    for rec in window_records:
        best_cat, best_sim, sec_cat, sec_sim = pattern_similarity(rec, attack_profiles)
        result.append({
            **rec,
            'reasons':              explain_alert(rec),
            'recommendations':      generate_recommendations(rec),
            'similar_pattern':      best_cat,
            'similarity_pct':       best_sim,
            'second_pattern':       sec_cat,
            'second_sim_pct':       sec_sim,
            'multi_baseline_view':  explain_multi_baseline(rec),
            'counterfactual':       counterfactual_analysis(rec, baselines or {}),
        })
    return result
