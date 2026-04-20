"""
INIDARS Demo - Replays actual NSL-KDD test records for realistic demonstrations.
The ML model was trained on 41 NSL-KDD features; this script sends those exact
features so the ensemble model receives proper input (not zero-padded garbage).

Usage:
  python demo.py mixed_traffic      # 40% Normal, 25% DoS, 20% Probe, 10% R2L, 5% U2R
  python demo.py dos                # 80% DoS attacks
  python demo.py probe              # 80% Probe / port scan
  python demo.py brute_force        # 80% R2L (remote-to-local, credential attacks)
  python demo.py malware            # 80% U2R (privilege escalation)
  python demo.py normal             # 100% normal traffic
  python demo.py mixed_traffic 120  # send 120 events instead of default 80
"""

import requests
import random
import time
import sys
import os
import pickle

import pandas as pd
import numpy as np

BASE_URL = "http://localhost:5000/api/events"

# ─── NSL-KDD schema (matches train_model.py) ──────────────────────────────────
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

ATTACK_MAP = {
    'normal': 'Normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS', 'worm': 'DoS',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
}

# Synthetic IPs per category (purely for dashboard display)
NORMAL_IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.3", "10.0.0.8"]
# Fixed IPs per category — same IP sends multiple events so rule engine accumulates
# (DDoSRule triggers at 15 events, PortScanRule at 10 unique ports, BruteForceRule at 3 fails)
ATTACK_IPS = {
    'DoS':   "45.33.32.156",
    'Probe': "103.21.244.0",
    'R2L':   "203.0.113.42",
    'U2R':   "91.108.56.1",
}

# NSL-KDD service → common dest port
SERVICE_PORT = {
    'http': 80, 'ftp': 21, 'smtp': 25, 'ssh': 22, 'telnet': 23,
    'finger': 79, 'pop_3': 110, 'imap4': 143, 'https': 443,
    'ftp_data': 20, 'domain': 53, 'bgp': 179, 'IRC': 6667,
    'X11': 6000, 'ldap': 389, 'klogin': 543, 'kshell': 544,
    'sql_net': 1521, 'sunrpc': 111, 'auth': 113, 'nntp': 119,
    'uucp': 540, 'gopher': 70, 'systat': 11, 'netstat': 15,
    'daytime': 13, 'time': 37, 'discard': 9, 'echo': 7,
}

FLAG_ACTION = {
    'SF': 'allow', 'S0': 'deny', 'REJ': 'reject',
    'RSTO': 'reset', 'SH': 'deny', 'OTH': 'unknown',
    'RSTOS0': 'reset', 'S1': 'allow', 'S2': 'allow', 'S3': 'allow',
}

SCENARIOS = {
    'mixed_traffic': {'Normal': 0.40, 'DoS': 0.25, 'Probe': 0.20, 'R2L': 0.10, 'U2R': 0.05},
    'dos':           {'Normal': 0.20, 'DoS': 0.80},
    'ddos':          {'Normal': 0.20, 'DoS': 0.80},
    'probe':         {'Normal': 0.20, 'Probe': 0.80},
    'port_scan':     {'Normal': 0.20, 'Probe': 0.80},
    'brute_force':   {'Normal': 0.20, 'R2L': 0.80},
    'malware':       {'Normal': 0.20, 'U2R': 0.80},
    'sql_injection': {'Normal': 0.20, 'R2L': 0.80},
    'normal':        {'Normal': 1.00},
}


def load_nslkdd():
    """Load KDDTest+.txt and apply the same categorical encoding used in training."""
    missing = [f for f in ('trained_model.pkl', 'KDDTest+.txt') if not os.path.exists(f)]
    if missing:
        print(f"[ERROR] Missing files: {', '.join(missing)}")
        print("  Run train_model.py first, and place KDDTest+.txt in backend/")
        sys.exit(1)

    print("Loading trained model encoders...", end=' ', flush=True)
    with open('trained_model.pkl', 'rb') as f:
        pkg = pickle.load(f)
    encoders    = pkg['encoders']
    feature_cols = pkg['feature_cols']
    print(f"OK ({len(feature_cols)} features)")

    print("Loading KDDTest+.txt...", end=' ', flush=True)
    df = pd.read_csv('KDDTest+.txt', names=COLUMN_NAMES)
    df['attack_category'] = df['label'].str.lower().map(lambda x: ATTACK_MAP.get(x, 'Normal'))

    # Preserve original string values for synthetic event fields
    df['_protocol_str'] = df['protocol_type'].astype(str)
    df['_service_str']  = df['service'].astype(str)
    df['_flag_str']     = df['flag'].astype(str)

    # Apply same encoding as training
    for col in ('protocol_type', 'service', 'flag'):
        le      = encoders[col]
        mapping = {cls: i for i, cls in enumerate(le.classes_)}
        df[col] = df[col].map(lambda x: mapping.get(x, 0))

    df = df.drop(columns=['difficulty'], errors='ignore')
    print(f"OK ({len(df):,} rows)")

    counts = df['attack_category'].value_counts()
    for cat, cnt in counts.items():
        print(f"  {cat:8s}: {cnt:6,} records")

    return df, feature_cols


def make_event(row, feature_cols):
    """Convert one NSL-KDD row into a /api/events payload."""
    category = row['attack_category']
    service  = row.get('_service_str', 'other')
    flag     = row.get('_flag_str',    'SF')
    protocol = row.get('_protocol_str','tcp')

    source_ip = (random.choice(NORMAL_IPS)
                 if category == 'Normal'
                 else ATTACK_IPS.get(category, '45.33.32.156'))

    dest_port = SERVICE_PORT.get(service, random.randint(1024, 65535))
    action    = FLAG_ACTION.get(flag, 'allow')
    if int(row.get('num_failed_logins', 0)) > 0:
        action = 'fail'

    # 41-feature vector (encoded but NOT yet scaled — detector.py scales internally)
    features = [float(row[col]) for col in feature_cols]

    return {
        'source_ip':          source_ip,
        'dest_ip':            '10.0.0.1',
        'source_port':        random.randint(1024, 65535),
        'dest_port':          int(dest_port),
        'protocol':           protocol,
        'action':             action,
        'bytes':              int(row.get('src_bytes', 0)),
        'bytes_recv':         int(row.get('dst_bytes', 0)),
        'packets':            max(1, int(row.get('count', 1))),
        'service':            service,
        '_nslkdd_features':   features,   # ← tells backend to skip basic feature extractor
        '_attack_category':   category,   # for console display only
    }


def send(event, idx, total):
    category = event.get('_attack_category', '?')
    prefix   = f"[{idx:03}/{total}]"
    try:
        r    = requests.post(BASE_URL, json=event, timeout=5)
        data = r.json()
        if data.get('alert_created'):
            sev    = data.get('severity', '?')
            msg    = data.get('message', '')
            print(f"{prefix} [ALERT/{sev:8s}] {event['source_ip']:16s} ({category}) → {msg}")
        elif data.get('status') == 'blocked':
            print(f"{prefix} [BLOCKED   ] {event['source_ip']}")
        else:
            print(f"{prefix} [Normal    ] {event['source_ip']:16s} ({category})")
    except requests.exceptions.ConnectionError:
        print(f"{prefix} [ERROR] Cannot connect. Is app.py running on port 5000?")
        sys.exit(1)
    except Exception as e:
        print(f"{prefix} [ERROR] {e}")


def run(scenario_name, count=80, delay=0.25):
    dist = SCENARIOS.get(scenario_name)
    if dist is None:
        print(f"Unknown scenario '{scenario_name}'.")
        print(f"Available: {', '.join(SCENARIOS)}")
        sys.exit(1)

    df, feature_cols = load_nslkdd()

    # Build per-category pools
    pools   = {}
    weights = {}
    for cat, w in dist.items():
        sub = df[df['attack_category'] == cat]
        if len(sub) == 0:
            print(f"  WARNING: no {cat} records in KDDTest+.txt — skipping")
            continue
        pools[cat]   = sub.reset_index(drop=True)
        weights[cat] = w

    if not pools:
        print("[ERROR] No records available for this scenario.")
        sys.exit(1)

    cats  = list(pools.keys())
    wvals = [weights[c] for c in cats]
    total = sum(wvals)
    wvals = [w / total for w in wvals]

    print(f"\n INIDARS Demo — scenario: {scenario_name} | {count} real NSL-KDD records\n")

    for i in range(1, count + 1):
        cat   = random.choices(cats, weights=wvals, k=1)[0]
        pool  = pools[cat]
        row   = pool.iloc[random.randint(0, len(pool) - 1)]
        event = make_event(row, feature_cols)
        send(event, i, count)
        time.sleep(delay)

    print(f"\nDone. {count} events sent from KDDTest+ ({scenario_name}).")


if __name__ == '__main__':
    scenario = sys.argv[1] if len(sys.argv) > 1 else 'mixed_traffic'
    count    = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    run(scenario, count)
