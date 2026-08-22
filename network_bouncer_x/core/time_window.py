import numpy as np
import pandas as pd
from collections import defaultdict


def compute_window_metrics(df: pd.DataFrame, known_peers: dict, window_size: int = 500) -> list:
    """
    Slide a window over detection-phase records and compute per-host metrics per window.
    Columns used: srcip, dstip, dsport, proto, dur, label, attack_cat

    Returns list of dicts — one per (srcip, window_index).
    """
    records = []
    for src, grp in df.groupby('srcip'):
        grp = grp.reset_index(drop=True)
        peers = known_peers.get(src, set())

        for win_idx, start in enumerate(range(0, len(grp), window_size)):
            w = grp.iloc[start:start + window_size]
            unique_dsts   = w['dstip'].nunique()
            unique_ports  = w['dsport'].nunique()
            conn_count    = len(w)
            avg_dur       = w['dur'].mean()
            new_peers     = set(w['dstip'].unique()) - peers
            new_peer_count = len(new_peers)
            new_peer_ratio = new_peer_count / max(unique_dsts, 1)
            dominant_proto = w['proto'].mode()[0] if len(w) else 'unknown'

            # Ground-truth for validation (from dataset)
            attack_present = int(w['label'].max())
            attack_cats    = list(w[w['label'] == 1]['attack_cat'].unique())

            records.append({
                'srcip':          src,
                'window':         win_idx,
                'unique_dsts':    unique_dsts,
                'unique_ports':   unique_ports,
                'conn_count':     conn_count,
                'avg_dur':        avg_dur,
                'new_peer_count': new_peer_count,
                'new_peer_ratio': new_peer_ratio,
                'new_peers_list': list(new_peers),
                'dominant_proto': dominant_proto,
                'attack_present': attack_present,
                'attack_cats':    attack_cats,
            })

            # Expand known peers progressively (sliding knowledge)
            peers = peers | set(w['dstip'].unique())

    return records


def build_global_baseline(baselines: dict) -> dict:
    """
    Compute global baseline across ALL hosts using MAD-filtered medians.
    Used as the third baseline layer (alongside host + peer-group).
    """
    from core.baseline import _mad_filter
    dsts  = _mad_filter(np.array([b['dest']['median']  for b in baselines.values()]))
    ports = _mad_filter(np.array([b['ports']['median'] for b in baselines.values()]))
    conns = _mad_filter(np.array([b['conns']['median'] for b in baselines.values()]))
    return {
        'dest':  float(np.median(dsts))  if len(dsts)  else 1.0,
        'ports': float(np.median(ports)) if len(ports) else 1.0,
        'conns': float(np.median(conns)) if len(conns) else 1.0,
    }


def compute_deviations(window_records: list, baselines: dict,
                       peer_group_baselines: dict, host_to_group: dict,
                       global_baseline: dict = None) -> list:
    """
    Three-baseline deviation system:
      - Host baseline    (50% weight when available)
      - Peer-group       (30% weight)
      - Global baseline  (20% weight)

    If host history < 5 windows: peer=60%, global=40% (no host baseline).

    Also stores individual deviations for explainability:
      host_dest_dev, peer_dest_dev, global_dest_dev (and same for ports/conns)
    """
    gb = global_baseline or {}
    enriched = []

    for rec in window_records:
        src    = rec['srcip']
        b      = baselines.get(src)
        pg_key = host_to_group.get(src)
        pg     = peer_group_baselines.get(pg_key, {}) if pg_key else {}
        sparse = (b is None or b.get('n_windows', 5) < 5)

        def _three_dev(current, b_key, pg_key_inner, gb_key):
            hb = b[b_key]['median']      if b      else None
            pb = pg.get(pg_key_inner, 1.0)
            gbv = gb.get(gb_key, 1.0)
            h_dev = current / max(hb,  1) if hb else None
            p_dev = current / max(pb,  1)
            g_dev = current / max(gbv, 1)
            if sparse or hb is None:
                combined = 0.6 * pb + 0.4 * gbv
            else:
                combined = 0.5 * hb + 0.3 * pb + 0.2 * gbv
            return (
                current / max(combined, 1),
                round(h_dev, 3) if h_dev else None,
                round(p_dev, 3),
                round(g_dev, 3)
            )

        dd,  hdd,  pdd,  gdd  = _three_dev(rec['unique_dsts'],  'dest',  'dest',  'dest')
        pd_,  hpd,  ppd,  gpd  = _three_dev(rec['unique_ports'], 'ports', 'ports', 'ports')
        bd,  hbd,  pbd,  gbd  = _three_dev(rec['conn_count'],   'conns', 'conns', 'conns')

        enriched.append({**rec,
                         'dest_dev':        round(dd,  3),
                         'port_dev':        round(pd_, 3),
                         'burst_dev':       round(bd,  3),
                         # Per-baseline breakdowns for explainability
                         'host_dest_dev':   hdd,  'peer_dest_dev':   pdd,  'global_dest_dev':   gdd,
                         'host_port_dev':   hpd,  'peer_port_dev':   ppd,  'global_port_dev':   gpd,
                         'host_burst_dev':  hbd,  'peer_burst_dev':  pbd,  'global_burst_dev':  gbd,
                         'used_peer_only':  sparse})
    return enriched


def add_persistence(window_records: list) -> list:
    """
    Track consecutive anomalous windows per host.
    A window is a candidate anomaly if any deviation > 2x.
    Adds 'persistence' field to each record.
    """
    persistence = defaultdict(int)
    result = []
    for rec in window_records:
        is_anomalous = (rec.get('dest_dev', 1) > 2 or
                        rec.get('port_dev', 1) > 2 or
                        rec.get('burst_dev', 1) > 2)
        if is_anomalous:
            persistence[rec['srcip']] += 1
        else:
            persistence[rec['srcip']] = max(0, persistence[rec['srcip']] - 1)
        result.append({**rec, 'persistence': persistence[rec['srcip']]})
    return result
