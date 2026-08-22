import warnings; warnings.filterwarnings('ignore')
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from core.loader import load

df = load(r'C:\Users\Admin\Downloads\UNSW-NB15_1.csv')
normal = df[df['label']==0]
attack = df[df['label']==1]

print('Normal rows:', len(normal))
print('Attack rows:', len(attack))
print()
print('Per-host breakdown:')
for src, grp in df.groupby('srcip'):
    n = len(grp[grp['label']==0])
    a = len(grp[grp['label']==1])
    u_dst = grp['dstip'].nunique()
    u_port = grp['dsport'].nunique()
    print(f'  {src}: normal={n}, attack={a}, unique_dsts={u_dst}, unique_ports={u_port}')
