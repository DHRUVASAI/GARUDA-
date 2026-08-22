import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


FEATURE_COLS = ['dest_dev', 'port_dev', 'burst_dev', 'new_peer_ratio', 'persistence']


def run_isolation_forest(window_records: list, contamination: float = 0.1) -> list:
    """
    Secondary ML validation layer using Isolation Forest.
    Adds 'ml_anomaly_score' (0-100) and 'ml_is_anomaly' (bool) to each record.
    Does NOT override rule-based decisions.
    """
    if not SKLEARN_AVAILABLE:
        return [{**r, 'ml_anomaly_score': None, 'ml_is_anomaly': None}
                for r in window_records]

    df = pd.DataFrame(window_records)[FEATURE_COLS].fillna(0)
    if len(df) < 10:
        return [{**r, 'ml_anomaly_score': None, 'ml_is_anomaly': None}
                for r in window_records]

    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    model.fit(df)

    raw_scores = model.decision_function(df)          # higher = more normal
    # Normalise to 0-100 where 100 = most anomalous
    norm = 1 - (raw_scores - raw_scores.min()) / (np.ptp(raw_scores) + 1e-9)
    ml_scores = (norm * 100).round(1)
    predictions = model.predict(df)                   # -1 = anomaly, 1 = normal

    result = []
    for rec, ml_score, pred in zip(window_records, ml_scores, predictions):
        result.append({
            **rec,
            'ml_anomaly_score': float(ml_score),
            'ml_is_anomaly':    bool(pred == -1),
        })
    return result
