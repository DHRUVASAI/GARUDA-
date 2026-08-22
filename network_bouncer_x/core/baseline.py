import numpy as np
import pandas as pd
from collections import defaultdict


# ── Robust statistics ────────────────────────────────────────────────────────

def _mad_filter(values: np.ndarray, threshold: float = 3.5) -> np.ndarray:
    """Remove outliers using Median Absolute Deviation. Returns clean array."""
    if len(values) < 3:
        return values
    med = np.median(values)
    mad = np.median(np.abs(values - med))
    if mad == 0:
        return values
    modified_z = 0.6745 * np.abs(values - med) / mad
    return values[modified_z <= threshold]


def _robust_stat(values) -> dict:
    arr = np.array(values, dtype=float)
    clean = _mad_filter(arr)
    if len(clean) == 0:
        clean = arr
    return {
        'median': float(np.median(clean)),
        'iqr':    float(np.percentile(clean, 75) - np.percentile(clean, 25)),
        'p75':    float(np.percentile(clean, 75)),
        'p90':    float(np.percentile(clean, 90)),
        'n':      len(clean)
    }


# ── Per-host baseline ────────────────────────────────────────────────────────

def build_host_baselines(df: pd.DataFrame) -> dict:
    """
    Compute robust per-host behavioral baselines.
    Columns used: srcip, dstip, dsport, proto, dur
    """
    baselines = {}
    for src, grp in df.groupby('srcip'):
        baselines[src] = {
            'dest':     _robust_stat(grp.groupby(grp.index // 1)['dstip'].nunique().values
                                     if False else
                                     [grp['dstip'].nunique()]),
            'ports':    _robust_stat([grp['dsport'].nunique()]),
            'conns':    _robust_stat([len(grp)]),
            'dur':      _robust_stat(grp['dur'].values),
            'top_proto': grp['proto'].mode()[0] if len(grp) else 'unknown',
            'known_peers': set(grp['dstip'].unique()),
        }
    return baselines


def build_windowed_host_baselines(df: pd.DataFrame, window_size: int = 500) -> dict:
    """
    Build baselines using sliding windows so each window is one observation.
    This prevents a single large traffic burst from poisoning the baseline.
    Columns used: srcip, dstip, dsport, proto, dur
    """
    baselines = {}
    for src, grp in df.groupby('srcip'):
        grp = grp.reset_index(drop=True)
        window_stats = defaultdict(list)
        for start in range(0, len(grp), window_size):
            w = grp.iloc[start:start + window_size]
            window_stats['dsts'].append(w['dstip'].nunique())
            window_stats['ports'].append(w['dsport'].nunique())
            window_stats['conns'].append(len(w))
            window_stats['dur'].append(w['dur'].mean())

        baselines[src] = {
            'dest':         _robust_stat(window_stats['dsts']),
            'ports':        _robust_stat(window_stats['ports']),
            'conns':        _robust_stat(window_stats['conns']),
            'dur':          _robust_stat(window_stats['dur']),
            'top_proto':    grp['proto'].mode()[0] if len(grp) else 'unknown',
            'known_peers':  set(grp['dstip'].unique()),
            'n_windows':    len(window_stats['dsts']),
        }
    return baselines


# ── Peer-group baseline ──────────────────────────────────────────────────────

def _port_bucket(median_port: float) -> str:
    if median_port < 1024:
        return 'low'
    elif median_port < 49152:
        return 'mid'
    return 'high'


def build_peer_groups(baselines: dict) -> dict:
    """
    Infer peer groups from protocol + port-range behavior.
    No predefined roles. Returns {group_key: [srcip, ...]}
    """
    groups = defaultdict(list)
    for src, b in baselines.items():
        bucket = _port_bucket(b['ports']['median'])
        key = f"{b['top_proto']}-{bucket}"
        groups[key].append(src)
    return dict(groups)


def build_peer_group_baselines(baselines: dict, peer_groups: dict) -> dict:
    """
    Compute peer-group median baselines.
    Returns {group_key: {dest_median, ports_median, conns_median}}
    """
    pg_baselines = {}
    for gkey, members in peer_groups.items():
        dsts   = _mad_filter(np.array([baselines[m]['dest']['median']  for m in members]))
        ports  = _mad_filter(np.array([baselines[m]['ports']['median'] for m in members]))
        conns  = _mad_filter(np.array([baselines[m]['conns']['median'] for m in members]))
        pg_baselines[gkey] = {
            'dest':  float(np.median(dsts))  if len(dsts)  else 1.0,
            'ports': float(np.median(ports)) if len(ports) else 1.0,
            'conns': float(np.median(conns)) if len(conns) else 1.0,
        }
    return pg_baselines


# ── Self-tuned deviation thresholds ─────────────────────────────────────────

def learn_deviation_thresholds(df: pd.DataFrame, baselines: dict) -> dict:
    """
    Learn Exploration / Scanning deviation thresholds from dataset.
    Uses 75th and 90th percentile of deviation distribution across all hosts.
    Columns used: label (to separate normal records)
    """
    normal_df = df[df['label'] == 0]
    deviations = []
    for src, grp in normal_df.groupby('srcip'):
        if src not in baselines:
            continue
        b = baselines[src]
        dest_base  = max(b['dest']['median'], 1)
        port_base  = max(b['ports']['median'], 1)
        d_dev = grp['dstip'].nunique() / dest_base
        p_dev = grp['dsport'].nunique() / port_base
        deviations.append(max(d_dev, p_dev))

    if not deviations:
        return {'exploration': 2.0, 'scanning': 4.0}

    arr = np.array(deviations)
    return {
        'exploration': float(np.percentile(arr, 75)),
        'scanning':    float(np.percentile(arr, 90)),
    }


def learn_score_weights(df: pd.DataFrame, baselines: dict,
                        window_size: int = 500) -> dict:
    """
    Derive score weights from point-biserial correlation of each feature with label.
    Uses per-window rows so both normal and attack windows contribute signal.
    Columns used: srcip, dstip, dsport, dur, label
    """
    from scipy.stats import pointbiserialr

    rows = []
    for src, grp in df.groupby('srcip'):
        if src not in baselines:
            continue
        b = baselines[src]
        dest_base = max(b['dest']['median'], 1)
        port_base = max(b['ports']['median'], 1)
        conn_base = max(b['conns']['median'], 1)
        grp = grp.reset_index(drop=True)
        for start in range(0, len(grp), window_size):
            w = grp.iloc[start:start + window_size]
            rows.append({
                'dest_dev':  w['dstip'].nunique()  / dest_base,
                'port_dev':  w['dsport'].nunique() / port_base,
                'burst_dev': len(w)                / conn_base,
                'peer_ratio': 0.0,
                'label':     int(w['label'].max())
            })

    if len(rows) < 10:
        return {'dest': 0.40, 'port': 0.30, 'burst': 0.20, 'peer': 0.10}

    feat_df = pd.DataFrame(rows)

    # Need at least 2 distinct label values for correlation
    if feat_df['label'].nunique() < 2:
        return {'dest': 0.40, 'port': 0.30, 'burst': 0.20, 'peer': 0.10}

    weights = {}
    for col in ['dest_dev', 'port_dev', 'burst_dev', 'peer_ratio']:
        try:
            if feat_df[col].nunique() < 2 or feat_df['label'].nunique() < 2:
                raise ValueError('constant input')
            r, _ = pointbiserialr(feat_df['label'], feat_df[col])
            val = abs(float(r))
            weights[col] = val if (val == val) else 0.01  # NaN guard
            weights[col] = max(weights[col], 0.01)
        except Exception:
            weights[col] = 0.01

    total = sum(weights.values())
    return {
        'dest':  round(weights['dest_dev']   / total, 4),
        'port':  round(weights['port_dev']   / total, 4),
        'burst': round(weights['burst_dev']  / total, 4),
        'peer':  round(weights['peer_ratio'] / total, 4),
    }


def learn_severity_bands(scores_for_attacks: list) -> dict:
    """
    Derive Low/Medium/High/Critical boundaries from score distribution
    of confirmed attack records. Enforces minimum 5-point spread between bands.
    """
    clean = [s for s in scores_for_attacks if s == s and s is not None]  # drop NaN
    if len(clean) < 4:
        return {'low': 30.0, 'medium': 55.0, 'high': 75.0}
    arr = np.array(clean)
    low    = float(np.percentile(arr, 25))
    medium = float(np.percentile(arr, 60))
    high   = float(np.percentile(arr, 85))
    # Enforce minimum 5-point spread so bands never collapse
    medium = max(medium, low    + 5.0)
    high   = max(high,   medium + 5.0)
    return {'low': round(low, 2), 'medium': round(medium, 2), 'high': round(high, 2)}
