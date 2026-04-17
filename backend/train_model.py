"""
INIDARS Phase 1 - Upgraded Model Training
Ensemble: XGBoost + LightGBM + Random Forest
Multi-class: Normal, DoS, Probe, R2L, U2R
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, classification_report)
import pickle
import warnings
warnings.filterwarnings('ignore')

# Try importing XGBoost and LightGBM
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️  XGBoost not found. Run: pip install xgboost")

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False
    print("⚠️  LightGBM not found. Run: pip install lightgbm")

# ─── NSL-KDD column names ────────────────────────────────────────────────────
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

# ─── Comprehensive NSL-KDD attack → category mapping ─────────────────────────
ATTACK_MAP = {
    'normal': 'Normal',
    # DoS
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS', 'worm': 'DoS',
    # Probe
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
}

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']


# ─── Data loading ─────────────────────────────────────────────────────────────
def load_data():
    print("Loading NSL-KDD dataset...")
    train_df = pd.read_csv('KDDTrain+.txt', names=COLUMN_NAMES).drop('difficulty', axis=1)
    test_df  = pd.read_csv('KDDTest+.txt',  names=COLUMN_NAMES).drop('difficulty', axis=1)
    print(f"  Train: {len(train_df):,} rows  |  Test: {len(test_df):,} rows")

    # Multi-class labels
    train_df['attack_category'] = train_df['label'].str.lower().map(
        lambda x: ATTACK_MAP.get(x, 'Normal'))
    test_df['attack_category']  = test_df['label'].str.lower().map(
        lambda x: ATTACK_MAP.get(x, 'Normal'))

    print("\nClass distribution (train):")
    for cls, cnt in train_df['attack_category'].value_counts().items():
        pct = cnt / len(train_df) * 100
        print(f"  {cls:8s}: {cnt:7,}  ({pct:.1f}%)")

    # Encode categorical columns
    cat_cols = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col])
        # Handle unseen labels in test set gracefully
        mapping = {cls: i for i, cls in enumerate(le.classes_)}
        test_df[col] = test_df[col].map(lambda x: mapping.get(x, -1))
        encoders[col] = le

    feature_cols = [c for c in train_df.columns
                    if c not in ('label', 'attack_category')]
    X_train_raw = train_df[feature_cols].values.astype(np.float32)
    X_test_raw  = test_df[feature_cols].values.astype(np.float32)

    # Encode target labels
    le_target = LabelEncoder()
    le_target.fit(CLASS_NAMES)
    y_train_all = le_target.transform(train_df['attack_category'])
    y_test      = le_target.transform(test_df['attack_category'])

    # 20% holdout from training data (same-distribution — what most papers use)
    from sklearn.model_selection import train_test_split as tts
    X_tr_raw, X_holdout_raw, y_train, y_holdout = tts(
        X_train_raw, y_train_all, test_size=0.20, random_state=42, stratify=y_train_all)

    scaler = StandardScaler()
    X_train   = scaler.fit_transform(X_tr_raw)
    X_holdout = scaler.transform(X_holdout_raw)
    X_test    = scaler.transform(X_test_raw)

    return X_train, X_holdout, X_test, y_train, y_holdout, y_test, scaler, encoders, feature_cols, le_target


from models import SoftVotingEnsemble   # shared so pickle can find it in detector.py too

# ─── Model training ───────────────────────────────────────────────────────────
def build_models(X_train, y_train):
    estimators = []

    # Compute balanced sample weights to handle severe R2L/U2R imbalance
    from sklearn.utils.class_weight import compute_sample_weight
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

    print("\nTraining Random Forest (200 trees, balanced)...")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=1,
        class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    estimators.append(('rf', rf))
    print("  Done.")

    if XGBOOST_AVAILABLE:
        print("Training XGBoost (200 rounds, balanced)...")
        xgb = XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric='mlogloss', random_state=42,
            n_jobs=-1, verbosity=0)
        xgb.fit(X_train, y_train, sample_weight=sample_weights)
        estimators.append(('xgb', xgb))
        print("  Done.")

    if LIGHTGBM_AVAILABLE:
        print("Training LightGBM (200 rounds, balanced)...")
        lgb = LGBMClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            num_leaves=50, class_weight='balanced',
            random_state=42, n_jobs=-1, verbose=-1)
        lgb.fit(X_train, y_train)
        estimators.append(('lgb', lgb))
        print("  Done.")

    if len(estimators) > 1:
        ensemble_type = ' + '.join(n.upper() for n, _ in estimators)
        print(f"\nBuilding soft-voting ensemble ({ensemble_type})...")
        ensemble = SoftVotingEnsemble(estimators)
    else:
        ensemble = estimators[0][1]
        ensemble_type = 'RandomForest'

    print(f"  Ensemble type: {ensemble_type}")
    return ensemble, {n: m for n, m in estimators}, ensemble_type


# ─── Evaluation ───────────────────────────────────────────────────────────────
def evaluate(ensemble, X_test, y_test, le_target):
    y_pred = ensemble.predict(X_test)

    normal_idx = le_target.transform(['Normal'])[0]
    y_test_bin = (y_test  != normal_idx).astype(int)
    y_pred_bin = (y_pred  != normal_idx).astype(int)

    def _m(yt, yp, avg='binary'):
        return {
            'accuracy':  float(accuracy_score(yt, yp)),
            'precision': float(precision_score(yt, yp, average=avg, zero_division=0)),
            'recall':    float(recall_score(yt, yp, average=avg, zero_division=0)),
            'f1':        float(f1_score(yt, yp, average=avg, zero_division=0)),
        }

    binary_m    = _m(y_test_bin, y_pred_bin)
    multiclass_m = _m(y_test, y_pred, avg='weighted')

    # Per-class
    per_class = {}
    for idx, cls in enumerate(le_target.classes_):
        mask = y_test == idx
        if mask.sum() == 0:
            continue
        per_class[cls] = {
            'precision': float(precision_score((y_test == idx).astype(int),
                                               (y_pred == idx).astype(int), zero_division=0)),
            'recall':    float(recall_score((y_test == idx).astype(int),
                                             (y_pred == idx).astype(int), zero_division=0)),
            'f1':        float(f1_score((y_test == idx).astype(int),
                                         (y_pred == idx).astype(int), zero_division=0)),
            'support':   int(mask.sum()),
        }

    print("\n" + "=" * 60)
    print("BINARY  (Normal vs Attack)")
    print("=" * 60)
    for k, v in binary_m.items():
        print(f"  {k:12s}: {v*100:.2f}%")

    print("\n" + "=" * 60)
    print("MULTI-CLASS  (5 categories — weighted avg)")
    print("=" * 60)
    for k, v in multiclass_m.items():
        print(f"  {k:12s}: {v*100:.2f}%")

    print("\nPer-class breakdown:")
    for cls, m in per_class.items():
        print(f"  {cls:8s}  P={m['precision']:.3f}  R={m['recall']:.3f}  "
              f"F1={m['f1']:.3f}  (n={m['support']:,})")

    return {'binary': binary_m, 'multiclass': multiclass_m, 'per_class': per_class}


# ─── Individual model metrics for comparison table ────────────────────────────
def eval_individual(models, X_test, y_test, le_target):
    results = {}
    normal_idx = le_target.transform(['Normal'])[0]
    for name, model in models.items():
        yp = model.predict(X_test)
        yp_bin = (yp != normal_idx).astype(int)
        yt_bin = (y_test != normal_idx).astype(int)
        results[name] = {
            'accuracy':  float(accuracy_score(yt_bin, yp_bin)),
            'precision': float(precision_score(yt_bin, yp_bin, zero_division=0)),
            'recall':    float(recall_score(yt_bin, yp_bin, zero_division=0)),
            'f1':        float(f1_score(yt_bin, yp_bin, zero_division=0)),
        }
    return results


# ─── Main ─────────────────────────────────────────────────────────────────────
def train_nsl_kdd_model():
    try:
        (X_train, X_holdout, X_test,
         y_train, y_holdout, y_test,
         scaler, encoders, feature_cols, le_target) = load_data()

        ensemble, ind_models, ensemble_type = build_models(X_train, y_train)

        print("\n" + "=" * 60)
        print("EVALUATION ON OFFICIAL KDDTest+ (harder — novel attacks)")
        print("=" * 60)
        metrics = evaluate(ensemble, X_test, y_test, le_target)
        ind_metrics = eval_individual(ind_models, X_test, y_test, le_target)

        # Same-distribution holdout: what most 99%+ papers actually use
        print("\n" + "=" * 60)
        print("EVALUATION ON 20% KDDTrain+ HOLDOUT (same-distribution)")
        print("This matches the methodology used in papers reporting 99%+")
        print("=" * 60)
        metrics_holdout = evaluate(ensemble, X_holdout, y_holdout, le_target)

        model_package = {
            'ensemble':           ensemble,
            'estimators':         ind_models,
            'ensemble_type':      ensemble_type,
            'scaler':             scaler,
            'encoders':           encoders,
            'feature_cols':       list(feature_cols),
            'label_encoder':      le_target,
            'class_names':        CLASS_NAMES,
            'metrics':            metrics,           # official KDDTest+
            'metrics_holdout':    metrics_holdout,   # same-distribution holdout
            'individual_metrics': ind_metrics,
            'dataset':            'NSL-KDD',
            'training_samples':   int(len(X_train)),
            'test_samples':       int(len(X_test)),
            'holdout_samples':    int(len(X_holdout)),
            # Keep old key for backward-compat with detector.py
            'random_forest':      ind_models.get('rf'),
        }

        with open('trained_model.pkl', 'wb') as f:
            pickle.dump(model_package, f)

        print("\n" + "=" * 60)
        print("Model saved to trained_model.pkl")
        b  = metrics['binary'];          bh = metrics_holdout['binary']
        mc = metrics['multiclass'];      mch = metrics_holdout['multiclass']
        print(f"\n  {'Metric':<20} {'KDDTest+ (hard)':>16} {'Holdout (easy)':>16}")
        print(f"  {'-'*54}")
        print(f"  {'Binary Accuracy':<20} {b['accuracy']*100:>15.2f}% {bh['accuracy']*100:>15.2f}%")
        print(f"  {'Binary F1':<20} {b['f1']*100:>15.2f}% {bh['f1']*100:>15.2f}%")
        print(f"  {'Multi-class Acc':<20} {mc['accuracy']*100:>15.2f}% {mch['accuracy']*100:>15.2f}%")
        print(f"  {'Multi-class F1':<20} {mc['f1']*100:>15.2f}% {mch['f1']*100:>15.2f}%")
        print("=" * 60)
        return model_package

    except FileNotFoundError:
        print("ERROR: KDDTrain+.txt / KDDTest+.txt not found in backend/")
        print("Download from: https://www.kaggle.com/datasets/hassan06/nslkdd")
        return None


if __name__ == '__main__':
    train_nsl_kdd_model()
