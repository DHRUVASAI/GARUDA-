# Network Bouncer X
**Context-Aware Behavioral Threat Detection for East-West Data Center Traffic**

---

## Quick Start

```bash
pip install -r requirements.txt
streamlit run dashboard/app.py
```

Upload any UNSW-NB15 CSV via the sidebar and click **Run Analysis**.

---

## Architecture

```
loader.py          → Ingest, clean, validate UNSW-NB15 columns
baseline.py        → MAD-robust windowed baselines + peer-group clustering
                     + self-tuned weights/thresholds from dataset
time_window.py     → Sliding window metrics + deviation ratios + persistence
scan_dna.py        → Horizontal / Vertical / Hybrid scan classification
threat_evolution.py→ Rule-based 4-stage threat level (thresholds from data)
score_engine.py    → ScanScore 0-100 + confidence + false-positive gate
story.py           → Window-indexed attack timeline (no timestamp needed)
explainability.py  → Evidence-mapped reasons + recommendations + pattern similarity
ml_extension.py    → Optional Isolation Forest secondary confidence layer
pipeline.py        → Orchestrates all modules end-to-end
dashboard/app.py   → Streamlit 7-tab SOC dashboard
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| MAD-based baseline | Resistant to contaminated training data (up to ~50% attack traffic) |
| Windowed baselines | Prevents single large burst from poisoning the host baseline |
| Dataset-learned weights | Point-biserial correlation with `label` column, not hardcoded |
| Dataset-learned thresholds | 75th/90th percentile of normal deviation distribution |
| Peer-group baseline | Protects against hosts with sparse or compromised history |
| Persistence gate | Suppresses single-window false positives (transient spikes) |
| Cosine similarity profiles | Compares host behavior against known attack patterns in dataset |
| Window-indexed timeline | Works without reliable timestamps |

---

## Dataset Columns Used

| Column | Used For |
|---|---|
| srcip | Host identity, grouping |
| dstip | Destination spread, new peer detection |
| dsport | Port diversity, scan DNA |
| proto | Peer group clustering |
| dur | Connection duration baseline |
| label | Weight learning, severity band learning, profile building |
| attack_cat | Attack pattern similarity profiles |
| sport, service, state | Available for future feature extension |

---

## False Positive Reduction

- Single-window anomalies → watch-only (no alert)
- Alert fires only after 2+ consecutive anomalous windows OR critical threshold breach
- Peer-group comparison prevents flagging hosts that are legitimately high-volume
- MAD filtering prevents attack traffic from inflating normal baselines
