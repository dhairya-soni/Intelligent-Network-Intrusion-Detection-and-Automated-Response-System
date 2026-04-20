"""
INIDARS Detection Engine - Phase 1
Ensemble: RF + XGBoost + LightGBM  |  Multi-class: Normal/DoS/Probe/R2L/U2R
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os
from models import SoftVotingEnsemble  # noqa: F401 — needed so pickle can deserialise saved ensembles

# ─── Feature explainability ───────────────────────────────────────────────────
# Names for the 10 features produced by feature_extractor.py
LIVE_FEATURE_NAMES = [
    'Source Port',        # 0
    'Destination Port',   # 1
    'Bytes Transferred',  # 2
    'Packet Count',       # 3
    'Protocol',           # 4
    'Action Type',        # 5
    'Source IP Pattern',  # 6
    'Dest IP Pattern',    # 7
    'Time of Day',        # 8
    'Payload Size',       # 9
]

# Expected value for each feature in NORMAL traffic (centre of normal range)
NORMAL_CENTRE = [0.85, 0.12, 0.18, 0.25, 0.25, 0.12, 0.50, 0.30, 0.50, 0.28]
NORMAL_STD    = [0.10, 0.10, 0.15, 0.20, 0.10, 0.08, 0.30, 0.20, 0.20, 0.18]

# Human-readable interpretation when a feature is highly anomalous
FEATURE_DESCRIPTIONS = [
    'Unusual ephemeral port activity',
    'Scanning/accessing sensitive destination port',
    'Abnormal data transfer volume',
    'Abnormal packet count — possible flood',
    'Uncommon or suspicious protocol',
    'Connection blocked, denied, or failed repeatedly',
    'Suspicious source IP addressing pattern',
    'Unusual destination address pattern',
    'Off-hours network activity',
    'Abnormal payload size (too large or fragmented)',
]

# ─── Attack category → human-readable threat type ─────────────────────────────
CATEGORY_THREAT_MAP = {
    'DoS':   ('DoS Attack',          'Denial-of-Service attack detected — high-volume traffic flooding the target',
                                      'Enable DDoS mitigation and rate-limit the source IP'),
    'Probe': ('Network Probe',        'Systematic reconnaissance or port-scanning activity detected',
                                      'Block source IP and review firewall rules'),
    'R2L':   ('Remote-to-Local',      'Unauthorised remote access attempt — possible credential theft',
                                      'Audit authentication logs and enforce MFA'),
    'U2R':   ('Privilege Escalation', 'Local user attempting to gain root/admin privileges',
                                      'Isolate endpoint and audit privilege-escalation paths'),
}

NORMAL_LABEL = 'Normal'


class INIDARSDetector:
    def __init__(self, use_trained_model=False):
        self.use_trained_model = use_trained_model
        self.model_package = None
        self.ensemble = None
        self.scaler = None
        self.label_encoder = None
        self.normal_idx = 0
        self.rules = self._initialize_rules()
        self.metrics = None

        if use_trained_model and os.path.exists('trained_model.pkl'):
            self._load_trained_model()
        else:
            self._fallback_model()

    # ── Loading ──────────────────────────────────────────────────────────────
    def _load_trained_model(self):
        try:
            with open('trained_model.pkl', 'rb') as f:
                pkg = pickle.load(f)
            self.model_package = pkg
            self.scaler = pkg['scaler']
            self.label_encoder = pkg.get('label_encoder')
            self.metrics = pkg.get('metrics', {})

            # Prefer ensemble; fall back to random_forest key (old format)
            if 'ensemble' in pkg and pkg['ensemble'] is not None:
                self.ensemble = pkg['ensemble']
            elif 'random_forest' in pkg:
                self.ensemble = pkg['random_forest']
            else:
                raise KeyError("No model found in package")

            if self.label_encoder is not None:
                classes = list(self.label_encoder.classes_)
                self.normal_idx = classes.index(NORMAL_LABEL) if NORMAL_LABEL in classes else 0

            b = self.metrics.get('binary', self.metrics)
            acc = b.get('accuracy', 0)
            f1  = b.get('f1', 0)
            etype = pkg.get('ensemble_type', 'Trained')
            print(f"Loaded model: {etype}")
            print(f"  Binary Accuracy: {acc*100:.2f}%  |  F1: {f1*100:.2f}%")
        except Exception as e:
            print(f"Could not load trained model: {e}")
            self._fallback_model()

    def _fallback_model(self):
        """Minimal Isolation Forest for demo mode."""
        model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
        model.fit(np.random.randn(1000, 10))
        self.ensemble = model
        self.metrics = {}

    def _initialize_rules(self):
        return [BruteForceRule(), PortScanRule(), SQLInjectionRule(),
                DDoSRule(), MalwareRule()]

    # ── Main detection entry ─────────────────────────────────────────────────
    def detect(self, features, event):
        ml_score, attack_category = self._ml_detect(features)
        rule_result = self._rule_detect(event)

        is_threat = ml_score > 0.35 or rule_result['matched']
        if not is_threat:
            return {
                'is_threat': False, 'threat_type': None,
                'attack_category': 'Normal',
                'ml_score': ml_score, 'rule_matched': False,
                'confidence': 0, 'description': 'Normal traffic',
                'recommendation': 'No action needed',
                'model_metrics': self.metrics,
                'explanation': None,
            }

        # Determine threat type / description / recommendation
        if rule_result['matched']:
            threat_type   = rule_result['rule_name']
            description   = rule_result['description']
            recommendation = rule_result['recommendation']
            # Use ML category if it agrees and isn't Normal
            if attack_category and attack_category != NORMAL_LABEL:
                cat_info = CATEGORY_THREAT_MAP.get(attack_category)
                if cat_info:
                    threat_type = cat_info[0]
                    description = cat_info[1]
                    recommendation = cat_info[2]
        elif attack_category and attack_category != NORMAL_LABEL:
            cat_info = CATEGORY_THREAT_MAP.get(attack_category, None)
            if cat_info:
                threat_type, description, recommendation = cat_info
            else:
                threat_type   = 'Anomalous Behavior'
                description   = f'ML anomaly detected (score: {ml_score:.2f})'
                recommendation = 'Investigate source IP'
        else:
            threat_type   = 'Anomalous Behavior'
            description   = f'ML anomaly detected (score: {ml_score:.2f})'
            recommendation = 'Investigate source IP'

        return {
            'is_threat':       True,
            'threat_type':     threat_type,
            'attack_category': attack_category or 'Unknown',
            'ml_score':        ml_score,
            'rule_matched':    rule_result['matched'],
            'confidence':      self._calculate_confidence(ml_score, rule_result['matched']),
            'description':     description,
            'recommendation':  recommendation,
            'model_metrics':   self.metrics,
            'explanation':     self.explain_prediction(features),
        }

    # ── ML scoring ───────────────────────────────────────────────────────────
    def _ml_detect(self, features):
        """Returns (anomaly_score 0-1, attack_category str or None)."""
        try:
            feat_arr = np.array(features, dtype=np.float32).reshape(1, -1)

            if self.scaler and self.model_package:
                expected = len(self.model_package['feature_cols'])
                cur = feat_arr.shape[1]
                if cur < expected:
                    feat_arr = np.hstack([feat_arr, np.zeros((1, expected - cur))])
                elif cur > expected:
                    feat_arr = feat_arr[:, :expected]
                feat_arr = self.scaler.transform(feat_arr)

            # Ensemble / RF with predict_proba
            if hasattr(self.ensemble, 'predict_proba'):
                proba = self.ensemble.predict_proba(feat_arr)[0]
                pred_idx = int(np.argmax(proba))
                # anomaly score = 1 - P(Normal)
                normal_prob = proba[self.normal_idx] if len(proba) > self.normal_idx else proba[0]
                ml_score = float(1.0 - normal_prob)

                if self.label_encoder is not None:
                    category = self.label_encoder.classes_[pred_idx]
                else:
                    category = NORMAL_LABEL if pred_idx == self.normal_idx else 'Unknown'
                return ml_score, category

            # Fallback: IsolationForest score_samples
            raw = self.ensemble.score_samples(feat_arr)[0]
            ml_score = float(max(0, min(1, -raw + 0.3)))
            return ml_score, None

        except Exception:
            return float(np.random.uniform(0.3, 0.8)), None

    # ── Rule-based detection ─────────────────────────────────────────────────
    def _rule_detect(self, event):
        for rule in self.rules:
            if rule.matches(event):
                return {'matched': True, 'rule_name': rule.name,
                        'description': rule.description,
                        'recommendation': rule.recommendation}
        return {'matched': False, 'rule_name': None,
                'description': None, 'recommendation': None}

    def explain_prediction(self, features):
        """
        Return per-feature anomaly contributions for this prediction.
        Uses z-score deviation from normal traffic baselines.
        Returns top 5 most anomalous features.
        """
        explanations = []
        for i, val in enumerate(features[:len(LIVE_FEATURE_NAMES)]):
            centre = NORMAL_CENTRE[i]
            std    = NORMAL_STD[i]
            z      = abs(val - centre) / max(std, 0.01)
            score  = round(min(1.0, z / 3.0), 3)   # 3-sigma → 1.0
            explanations.append({
                'feature':      LIVE_FEATURE_NAMES[i],
                'value':        round(float(val), 3),
                'anomaly_score': score,
                'normal_low':   round(centre - std, 3),
                'normal_high':  round(centre + std, 3),
                'description':  FEATURE_DESCRIPTIONS[i] if score > 0.5 else 'Within normal range',
            })

        # Also pull global feature importance from RF if available
        global_importance = None
        if self.model_package and 'estimators' in self.model_package:
            rf = self.model_package['estimators'].get('rf')
            if rf and hasattr(rf, 'feature_importances_'):
                cols = self.model_package.get('feature_cols', [])
                imps = rf.feature_importances_
                global_importance = sorted(
                    [{'feature': c, 'importance': round(float(v), 4)}
                     for c, v in zip(cols, imps)],
                    key=lambda x: x['importance'], reverse=True
                )[:10]

        explanations.sort(key=lambda x: x['anomaly_score'], reverse=True)
        return {
            'live_features':      explanations[:5],
            'global_importance':  global_importance,
        }

    def _calculate_confidence(self, ml_score, rule_matched):
        if rule_matched and ml_score > 0.75: return 95
        if rule_matched and ml_score > 0.60: return 85
        if rule_matched:                      return 75
        if ml_score > 0.80:                   return 80
        if ml_score > 0.65:                   return 65
        if ml_score > 0.50:                   return 55
        return 45

    # ── Model info for API ────────────────────────────────────────────────────
    def get_model_info(self):
        if not self.metrics:
            return {'type': 'Isolation Forest (Demo)', 'accuracy': 'N/A',
                    'training_samples': 'Simulated', 'features': '10 basic'}

        pkg = self.model_package or {}
        b  = self.metrics.get('binary', self.metrics)
        mc = self.metrics.get('multiclass', {})
        pc = self.metrics.get('per_class', {})

        return {
            'type':              pkg.get('ensemble_type', 'Trained Model'),
            'dataset':           pkg.get('dataset', 'NSL-KDD'),
            'training_samples':  f"{pkg.get('training_samples', 0):,}",
            'test_samples':      f"{pkg.get('test_samples', 0):,}",
            'features':          f"{len(pkg.get('feature_cols', []))} network features",
            'classes':           pkg.get('class_names', ['Normal', 'Attack']),
            # Binary
            'accuracy':          f"{b.get('accuracy', 0)*100:.2f}%",
            'precision':         f"{b.get('precision', 0)*100:.2f}%",
            'recall':            f"{b.get('recall', 0)*100:.2f}%",
            'f1':                f"{b.get('f1', 0)*100:.2f}%",
            # Multi-class
            'multiclass_accuracy':  f"{mc.get('accuracy', 0)*100:.2f}%",
            'multiclass_precision': f"{mc.get('precision', 0)*100:.2f}%",
            'multiclass_recall':    f"{mc.get('recall', 0)*100:.2f}%",
            'multiclass_f1':        f"{mc.get('f1', 0)*100:.2f}%",
            # Per-class
            'per_class_metrics': pc,
            # Raw floats for the benchmark page
            'raw': {
                'binary': b,
                'multiclass': mc,
                'per_class': pc,
                'individual': pkg.get('individual_metrics', {}),
            }
        }


# ─── Rule classes ─────────────────────────────────────────────────────────────
class DetectionRule:
    def __init__(self, name, description, recommendation):
        self.name = name
        self.description = description
        self.recommendation = recommendation

    def matches(self, event):
        raise NotImplementedError


class BruteForceRule(DetectionRule):
    def __init__(self):
        super().__init__('Brute Force Attack',
                         'Multiple failed authentication attempts detected',
                         'Block IP and enable rate limiting')
        self.failed = {}

    def matches(self, event):
        ip = event.get('source_ip', '')
        action = event.get('action', '').lower()
        if 'fail' in action or 'denied' in action:
            self.failed[ip] = self.failed.get(ip, 0) + 1
            if self.failed[ip] >= 3:
                return True
        return False


class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__('Port Scan',
                         'Systematic port scanning detected',
                         'Block source IP immediately')
        self.ports = {}

    def matches(self, event):
        ip = event.get('source_ip', '')
        port = event.get('dest_port', 0)
        self.ports.setdefault(ip, set()).add(port)
        return len(self.ports[ip]) > 5


class SQLInjectionRule(DetectionRule):
    def __init__(self):
        super().__init__('SQL Injection Attempt',
                         'Malicious SQL patterns detected in payload',
                         'Block request and audit application')
        self.patterns = ['union select', 'drop table', '1=1', '--',
                         'exec(', 'xp_cmdshell', "'; ", 'or 1=1']

    def matches(self, event):
        raw = str(event.get('raw_data', '')).lower()
        return any(p in raw for p in self.patterns)


class DDoSRule(DetectionRule):
    def __init__(self):
        super().__init__('DDoS Attack',
                         'High-volume traffic flood detected from single source',
                         'Enable DDoS mitigation and rate limiting')
        self.counts = {}

    def matches(self, event):
        ip = event.get('source_ip', '')
        self.counts[ip] = self.counts.get(ip, 0) + 1
        return self.counts[ip] > 15


class MalwareRule(DetectionRule):
    def __init__(self):
        super().__init__('Malware Activity',
                         'Suspicious process or file execution pattern detected',
                         'Isolate endpoint and run full antivirus scan')
        self.patterns = ['malware', 'trojan', 'suspicious.exe',
                         'powershell -enc', 'cmd.exe /c', 'wget http',
                         'curl http', '/bin/sh', 'base64 -d']

    def matches(self, event):
        raw = str(event.get('raw_data', '')).lower()
        return any(p in raw for p in self.patterns)
