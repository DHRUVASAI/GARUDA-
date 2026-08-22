import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from pipeline import run_pipeline

res = run_pipeline(
    r'C:\Users\Admin\Downloads\UNSW-NB15_1.csv',
    window_size=500, baseline_ratio=0.4, enable_ml=False
)
s = res['summary']
print('Total hosts:     ', s['total_hosts'])
print('Suspicious hosts:', s['suspicious_hosts'])
print('Critical hosts:  ', s['critical_hosts'])
print('Total alerts:    ', s['total_alerts'])
print('Weights learned: ', s['weights'])
print('Thresholds:      ', s['dev_thresholds'])
print('Severity bands:  ', s['severity_bands'])

# Show top alert if any
recs = [r for r in res['records'] if r.get('is_alert')]
if recs:
    top = sorted(recs, key=lambda x: x['scan_score'], reverse=True)[0]
    print('\nTop alert host:  ', top['srcip'])
    print('Score:           ', top['scan_score'])
    print('Reasons:         ', top['reasons'])
    print('Recommendations: ', top['recommendations'])
