import pandas as pd
import numpy as np

REQUIRED_COLS = {'srcip', 'dstip', 'sport', 'dsport', 'proto', 'service', 'state', 'dur', 'label', 'attack_cat'}

# Official UNSW-NB15 column order (headerless CSV)
UNSW_COLUMNS = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur',
    'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
    'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'sjit', 'djit',
    'stime', 'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'label'
]

def _has_header(path: str) -> bool:
    """Detect whether CSV has a header row by checking if first cell is a known column name."""
    with open(path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        first = f.readline().split(',')[0].strip().lower()
    # Known header names in UNSW-NB15 with-header variants
    known_headers = {'srcip', 'source ip', 'src_ip', 'src ip'}
    return first in known_headers

def load(path: str, chunksize: int = None) -> pd.DataFrame:
    """Load UNSW-NB15 CSV, clean and validate columns."""
    has_hdr = _has_header(path)

    read_kwargs = dict(low_memory=False, encoding='utf-8-sig')
    if not has_hdr:
        read_kwargs['header'] = None
        read_kwargs['names'] = UNSW_COLUMNS

    if chunksize:
        chunks = pd.read_csv(path, chunksize=chunksize, **read_kwargs)
        df = pd.concat(chunks, ignore_index=True)
    else:
        df = pd.read_csv(path, **read_kwargs)

    df.columns = df.columns.str.strip().str.lower()

    # Remap common alternate column names (for files that do have headers)
    remap = {'source ip': 'srcip', 'dest ip': 'dstip', 'source port': 'sport',
             'dest port': 'dsport', 'duration': 'dur', 'category': 'attack_cat'}
    df.rename(columns=remap, inplace=True)

    missing = REQUIRED_COLS - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    # Clean
    df['dur'] = pd.to_numeric(df['dur'], errors='coerce').fillna(0)
    df['sport'] = pd.to_numeric(df['sport'], errors='coerce').fillna(0).astype(int)
    df['dsport'] = pd.to_numeric(df['dsport'], errors='coerce').fillna(0).astype(int)
    df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
    df['attack_cat'] = df['attack_cat'].fillna('Normal').str.strip()
    df['proto'] = df['proto'].fillna('unknown').str.lower().str.strip()
    df['service'] = df['service'].fillna('-').str.lower().str.strip()
    df['srcip'] = df['srcip'].fillna('0.0.0.0').str.strip()
    df['dstip'] = df['dstip'].fillna('0.0.0.0').str.strip()

    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def split_baseline_detection(df: pd.DataFrame, baseline_ratio: float = 0.4):
    """Split dataset into baseline learning phase and detection phase."""
    split = int(len(df) * baseline_ratio)
    return df.iloc[:split].copy(), df.iloc[split:].copy()
