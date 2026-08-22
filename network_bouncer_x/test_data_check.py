import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import warnings; warnings.filterwarnings('ignore')
import numpy as np
from core.loader import load, split_baseline_detection
from core.baseline import build_windowed_host_baselines

df = load(r'C:\Users\Admin\Downloads\UNSW-NB15_1.csv')
print('Total rows:', len(df))
print('Label dist:', df['label'].value_counts().to_dict())
print('Unique srcips:', df['srcip'].nunique())
print('Rows per srcip (top 5):')
print(df.groupby('srcip').size().sort_values(ascending=False).head().to_string())

base_df, det_df = split_baseline_detection(df, 0.4)
print('\nBaseline rows:', len(base_df), '| attack in baseline:', int(base_df['label'].sum()))
print('Detection rows:', len(det_df), '| attack in detection:', int(det_df['label'].sum()))

# Check per-host window deviations in detection phase
baselines = build_windowed_host_baselines(base_df, 500)
print('\nSample baselines (first 3 hosts):')
for i, (src, b) in enumerate(list(baselines.items())[:3]):
    print(f"  {src}: dest_median={b['dest']['median']:.1f}, port_median={b['ports']['median']:.1f}, n_windows={b['n_windows']}")

# Check detection deviations
print('\nSample detection deviations:')
for src, grp in det_df.groupby('srcip'):
    if src not in baselines: continue
    b = baselines[src]
    dest_dev = grp['dstip'].nunique() / max(b['dest']['median'], 1)
    port_dev = grp['dsport'].nunique() / max(b['ports']['median'], 1)
    print(f"  {src}: dest_dev={dest_dev:.2f}x, port_dev={port_dev:.2f}x, attack_rows={int(grp['label'].sum())}")
