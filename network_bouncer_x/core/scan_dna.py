import numpy as np
import pandas as pd


def classify_scan_dna(unique_dsts: int, unique_ports: int,
                      dst_threshold: float, port_threshold: float) -> str:
    """
    Classify scan type based on destination and port spread.
    Thresholds are dataset-derived (passed in from baseline learning).

    Horizontal : many destinations, few ports  → sweeping one service across hosts
    Vertical   : few destinations, many ports  → enumerating one host's services
    Hybrid     : many destinations, many ports → full reconnaissance
    Normal     : neither threshold breached
    """
    high_dst  = unique_dsts  >= dst_threshold
    high_port = unique_ports >= port_threshold

    if high_dst and high_port:
        return 'Hybrid'
    if high_dst:
        return 'Horizontal'
    if high_port:
        return 'Vertical'
    return 'Normal'


def learn_scan_thresholds(df: pd.DataFrame, baselines: dict) -> dict:
    """
    Derive scan DNA thresholds from the 90th percentile of
    destination/port counts in normal traffic.
    Columns used: srcip, dstip, dsport, label
    """
    normal = df[df['label'] == 0]
    dst_counts, port_counts = [], []
    for src, grp in normal.groupby('srcip'):
        dst_counts.append(grp['dstip'].nunique())
        port_counts.append(grp['dsport'].nunique())

    dst_t  = float(np.percentile(dst_counts,  90)) if dst_counts  else 10.0
    port_t = float(np.percentile(port_counts, 90)) if port_counts else 10.0
    return {'dst_threshold': dst_t, 'port_threshold': port_t}


def apply_scan_dna(window_records: list, scan_thresholds: dict) -> list:
    """Annotate every window record with its Scan DNA classification."""
    dst_t  = scan_thresholds['dst_threshold']
    port_t = scan_thresholds['port_threshold']
    return [
        {**rec, 'scan_dna': classify_scan_dna(
            rec['unique_dsts'], rec['unique_ports'], dst_t, port_t)}
        for rec in window_records
    ]
