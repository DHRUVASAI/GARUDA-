import numpy as np
from collections import defaultdict


def detect_behavioral_drift(window_records: list, min_windows: int = 4) -> dict:
    """
    Detect slow behavioral drift per host — the case where no single window
    looks like a spike but the trend is consistently growing.

    Method:
      For each host, collect window-by-window dest_dev and port_dev values.
      Fit a linear trend (slope via least squares).
      If slope > 0 and R² > 0.6 across min_windows observations → drift detected.

    Returns: {srcip: {drift_detected, slope, r2, metric, window_values}}
    Columns used: srcip (indirectly via pre-computed window records)
    """
    host_series = defaultdict(lambda: defaultdict(list))

    for rec in sorted(window_records, key=lambda r: (r['srcip'], r['window'])):
        src = rec['srcip']
        host_series[src]['dest_dev'].append(rec.get('dest_dev', 1.0))
        host_series[src]['port_dev'].append(rec.get('port_dev', 1.0))
        host_series[src]['burst_dev'].append(rec.get('burst_dev', 1.0))

    results = {}
    for src, series in host_series.items():
        best = {'drift_detected': False, 'slope': 0.0, 'r2': 0.0,
                'metric': None, 'window_values': []}

        for metric, values in series.items():
            if len(values) < min_windows:
                continue
            arr = np.array(values, dtype=float)
            x   = np.arange(len(arr), dtype=float)
            # Least-squares linear fit
            slope, intercept = np.polyfit(x, arr, 1)
            y_pred = slope * x + intercept
            ss_res = np.sum((arr - y_pred) ** 2)
            ss_tot = np.sum((arr - arr.mean()) ** 2)
            r2     = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0

            # Drift: positive slope AND good linear fit AND starts near-normal
            if (slope > 0.05 and r2 > 0.6 and
                    arr[0] < 3.0 and arr[-1] > arr[0] * 1.5):
                if slope > best['slope']:
                    best = {
                        'drift_detected': True,
                        'slope':          round(float(slope), 4),
                        'r2':             round(float(r2), 3),
                        'metric':         metric,
                        'window_values':  [round(float(v), 2) for v in arr],
                        'start_val':      round(float(arr[0]), 2),
                        'end_val':        round(float(arr[-1]), 2),
                    }
        results[src] = best

    return results


def drift_summary(drift_results: dict) -> dict:
    """Aggregate drift detection stats for dashboard."""
    drifting = {s: d for s, d in drift_results.items() if d['drift_detected']}
    return {
        'drifting_hosts':   len(drifting),
        'drift_details':    drifting,
    }
