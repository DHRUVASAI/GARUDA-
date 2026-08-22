import pandas as pd
import numpy as np
from core.loader           import load
from core.baseline         import (build_windowed_host_baselines, build_peer_groups,
                                    build_peer_group_baselines, learn_deviation_thresholds,
                                    learn_score_weights, learn_severity_bands)
from core.time_window      import (compute_window_metrics, build_global_baseline,
                                    compute_deviations, add_persistence)
from core.scan_dna         import learn_scan_thresholds, apply_scan_dna
from core.threat_evolution import apply_threat_evolution
from core.score_engine     import apply_fp_guard, compute_risk_stability
from core.ensemble         import run_ensemble
from core.attack_graph     import build_attack_graph, graph_summary
from core.drift            import detect_behavioral_drift, drift_summary
from core.story            import build_all_stories
from core.explainability   import build_attack_profiles, enrich_with_explainability
from core.soc_triage       import enrich_soc_features
from core.ml_extension     import run_isolation_forest


def _per_host_split(df: pd.DataFrame, baseline_ratio: float) -> tuple:
    """Per-host split: baseline from first N% of each host's NORMAL rows only."""
    baseline_rows, detection_rows = [], []
    for src, grp in df.groupby('srcip'):
        grp    = grp.reset_index(drop=True)
        normal = grp[grp['label'] == 0]
        if len(normal) > 0:
            split = max(1, int(len(normal) * baseline_ratio))
            baseline_rows.append(normal.iloc[:split])
        else:
            split = max(1, int(len(grp) * baseline_ratio))
            baseline_rows.append(grp.iloc[:split])
        detection_rows.append(grp)
    b_df = pd.concat(baseline_rows, ignore_index=True) if baseline_rows else pd.DataFrame()
    d_df = pd.concat(detection_rows, ignore_index=True) if detection_rows else pd.DataFrame()
    return (b_df, d_df)


def run_pipeline(csv_path: str, window_size: int = 500,
                 baseline_ratio: float = 0.4, enable_ml: bool = True) -> dict:
    """
    Network Bouncer X — Full Detection Pipeline

    Baseline strategy  : per-host normal-only rows (poison-resistant)
    Deviation system   : 3-baseline (host 50% + peer 30% + global 20%)
    Detection          : all rows windowed per host
    Ensemble           : 5 independent detectors + voting
    Drift              : monotonic trend detection across windows
    Attack graph       : communication chain + lateral movement
    Explainability     : reasons + counterfactual + multi-baseline view
    """
    # 1. Load
    df = load(csv_path)

    # 2. Per-host baseline split
    baseline_df, detection_df = _per_host_split(df, baseline_ratio)

    # 3. Build all 3 baseline layers
    baselines     = build_windowed_host_baselines(baseline_df, window_size)
    peer_groups   = build_peer_groups(baselines)
    pg_baselines  = build_peer_group_baselines(baselines, peer_groups)
    global_base   = build_global_baseline(baselines)
    host_to_group = {src: gk for gk, members in peer_groups.items() for src in members}

    # 4. Self-tune all thresholds from normal traffic
    dev_thresholds  = learn_deviation_thresholds(baseline_df, baselines)
    scan_thresholds = learn_scan_thresholds(baseline_df, baselines)
    weights         = learn_score_weights(df, baselines, window_size)
    attack_profiles = build_attack_profiles(df)

    # 5. Windowed detection over ALL rows
    known_peers    = {src: b['known_peers'] for src, b in baselines.items()}
    window_records = compute_window_metrics(detection_df, known_peers, window_size)
    window_records = compute_deviations(window_records, baselines,
                                        pg_baselines, host_to_group, global_base)
    window_records = add_persistence(window_records)

    # 6. Scan DNA
    window_records = apply_scan_dna(window_records, scan_thresholds)

    # 7. Ensemble rule engine (5 detectors + voting)
    window_records = run_ensemble(window_records, dev_thresholds, baselines)

    # 8. Provisional score pass for threat level
    provisional = apply_fp_guard(window_records,
                                 {'low': 30, 'medium': 55, 'high': 75}, weights)
    for i, rec in enumerate(provisional):
        window_records[i]['scan_score'] = rec['scan_score']

    # 9. Threat evolution
    window_records = apply_threat_evolution(window_records, dev_thresholds)

    # 10. Final scoring with learned severity bands
    attack_scores  = [r['scan_score'] for r in window_records if r.get('attack_present')]
    bands          = learn_severity_bands(attack_scores)
    window_records = apply_fp_guard(window_records, bands, weights)

    # 11. Risk stability
    window_records = compute_risk_stability(window_records)

    # 12. Behavioral drift detection
    drift_results  = detect_behavioral_drift(window_records)
    drift_info     = drift_summary(drift_results)
    # Annotate each record with its host's drift result
    for rec in window_records:
        d = drift_results.get(rec['srcip'], {})
        rec['drift_detected'] = d.get('drift_detected', False)
        rec['drift_slope']    = d.get('slope', 0.0)
        rec['drift_metric']   = d.get('metric', None)

    # 13. Attack graph
    attack_graph = build_attack_graph(window_records,
                                      alert_threshold=bands.get('low', 30))
    graph_info   = graph_summary(attack_graph)

    # 14. Explainability (multi-baseline + counterfactual)
    window_records = enrich_with_explainability(window_records, attack_profiles, baselines)

    # 15. SOC triage features
    window_records, triage_queue, suppression_log = enrich_soc_features(
        window_records, baselines, pg_baselines, host_to_group, bands)

    # 16. Optional ML layer
    if enable_ml:
        window_records = run_isolation_forest(window_records)

    # 17. Attack stories
    stories = build_all_stories(window_records)

    # 18. Summary
    alert_records = [r for r in window_records if r.get('is_alert')]
    drift_hosts   = [r['srcip'] for r in window_records if r.get('drift_detected')]
    summary = {
        'total_hosts':        len(set(r['srcip'] for r in window_records)),
        'suspicious_hosts':   len(set(r['srcip'] for r in alert_records)),
        'critical_hosts':     len(set(r['srcip'] for r in alert_records
                                      if r.get('severity') == 'Critical')),
        'drift_hosts':        len(set(drift_hosts)),
        'total_windows':      len(window_records),
        'total_alerts':       len(alert_records),
        'weights':            weights,
        'dev_thresholds':     dev_thresholds,
        'scan_thresholds':    scan_thresholds,
        'severity_bands':     bands,
        'graph_info':         graph_info,
        'drift_info':         drift_info,
        'peer_groups':        {k: len(v) for k, v in peer_groups.items()},
    }

    return {
        'records':         window_records,
        'stories':         stories,
        'summary':         summary,
        'baselines':       baselines,
        'weights':         weights,
        'thresholds':      dev_thresholds,
        'bands':           bands,
        'attack_graph':    attack_graph,
        'drift':           drift_results,
        'peer_groups':     peer_groups,
        'triage_queue':    triage_queue,
        'suppression_log': suppression_log,
        'pg_baselines':    pg_baselines,
        'host_to_group':   host_to_group,
    }
