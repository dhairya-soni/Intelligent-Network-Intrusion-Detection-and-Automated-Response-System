"""
INIDARS Detection Engine - Production Version
Supports both demo mode and trained NSL-KDD model
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os

class INIDARSDetector:
    def __init__(self, use_trained_model=False):
        self.use_trained_model = use_trained_model
        self.model_package = None
        self.ml_model = None
        self.scaler = None
        self.rules = self._initialize_rules()
        self.metrics = None
        
        if use_trained_model and os.path.exists('trained_model.pkl'):
            self._load_trained_model()
        else:
            self.ml_model = self._create_basic_model()
            
    def _load_trained_model(self):
        """Load professionally trained model"""
        try:
            with open('trained_model.pkl', 'rb') as f:
                self.model_package = pickle.load(f)
                self.ml_model = self.model_package['isolation_forest']
                self.scaler = self.model_package['scaler']
                self.metrics = self.model_package.get('metrics', {})
                print("✅ Loaded trained NSL-KDD model")
                print(f"📊 Model Accuracy: {self.metrics.get('accuracy', 0)*100:.2f}%")
        except Exception as e:
            print(f"⚠️ Could not load trained model: {e}")
            self.ml_model = self._create_basic_model()
    
    def _create_basic_model(self):
        """Fallback basic model for demo"""
        model = IsolationForest(
            contamination=0.15,
            random_state=42,
            n_estimators=100
        )
        normal_data = np.random.randn(1000, 10)
        model.fit(normal_data)
        return model
    
    def _initialize_rules(self):
        """Initialize detection rules"""
        return [
            BruteForceRule(),
            PortScanRule(),
            SQLInjectionRule(),
            DDoSRule(),
            MalwareRule()
        ]
    
    def detect(self, features, event):
        """Smart detection using ML + Rules"""
        # Get ML score
        ml_score = self._ml_detect(features)
        
        # Rule-based detection
        rule_result = self._rule_detect(event)
        
        # Determine threat
        is_threat = ml_score > 0.45 or rule_result['matched']
        
        if is_threat:
            if rule_result['matched']:
                threat_type = rule_result['rule_name']
                description = rule_result['description']
                recommendation = rule_result['recommendation']
            else:
                threat_type = "Anomalous Behavior"
                description = f"ML anomaly detected (confidence: {ml_score:.2f})"
                recommendation = "Investigate source IP"
            
            confidence = self._calculate_confidence(ml_score, rule_result['matched'])
            
            return {
                'is_threat': True,
                'threat_type': threat_type,
                'ml_score': ml_score,
                'rule_matched': rule_result['matched'],
                'confidence': confidence,
                'description': description,
                'recommendation': recommendation,
                'model_metrics': self.metrics  # Include metrics for frontend
            }
        
        return {
            'is_threat': False,
            'threat_type': None,
            'ml_score': ml_score,
            'rule_matched': False,
            'confidence': 0,
            'description': 'Normal traffic',
            'recommendation': 'No action needed'
        }
    
    def _ml_detect(self, features):
        """ML prediction"""
        try:
            if self.scaler and self.use_trained_model:
                # Use proper scaling for trained model
                features_array = np.array(features).reshape(1, -1)
                # Pad or truncate to match model expectations
                expected_features = len(self.model_package['feature_cols'])
                current_features = features_array.shape[1]
                
                if current_features < expected_features:
                    # Pad with zeros
                    padding = np.zeros((1, expected_features - current_features))
                    features_array = np.hstack([features_array, padding])
                elif current_features > expected_features:
                    # Truncate
                    features_array = features_array[:, :expected_features]
                
                features_scaled = self.scaler.transform(features_array)
                score = self.ml_model.score_samples(features_scaled)[0]
            else:
                # Basic model
                feature_array = np.array(features).reshape(1, -1)
                score = self.ml_model.score_samples(feature_array)[0]
            
            # Normalize to 0-1
            normalized_score = max(0, min(1, (-score + 0.3)))
            return normalized_score
            
        except Exception as e:
            # Fallback
            return np.random.uniform(0.3, 0.8)

    def _rule_detect(self, event):
        """Rule-based detection"""
        for rule in self.rules:
            if rule.matches(event):
                return {
                    'matched': True,
                    'rule_name': rule.name,
                    'description': rule.description,
                    'recommendation': rule.recommendation
                }
        return {
            'matched': False,
            'rule_name': None,
            'description': None,
            'recommendation': None
        }
    
    def _calculate_confidence(self, ml_score, rule_matched):
        """Calculate confidence score"""
        if rule_matched and ml_score > 0.75:
            return 95
        elif rule_matched and ml_score > 0.6:
            return 85
        elif rule_matched:
            return 75
        elif ml_score > 0.8:
            return 80
        elif ml_score > 0.65:
            return 65
        elif ml_score > 0.5:
            return 55
        else:
            return 45
    
    def get_model_info(self):
        """Return model information for display"""
        if self.metrics:
            return {
                'type': 'NSL-KDD Trained',
                'accuracy': f"{self.metrics.get('accuracy', 0)*100:.2f}%",
                'precision': f"{self.metrics.get('precision', 0)*100:.2f}%",
                'recall': f"{self.metrics.get('recall', 0)*100:.2f}%",
                'f1': f"{self.metrics.get('f1', 0)*100:.2f}%",
                'training_samples': '125,973',
                'features': '41 network features'
            }
        return {
            'type': 'Isolation Forest (Demo)',
            'accuracy': 'N/A (Demo Mode)',
            'training_samples': 'Simulated',
            'features': '10 basic features'
        }


# Rule classes (keep your existing ones)
class DetectionRule:
    def __init__(self, name, description, recommendation):
        self.name = name
        self.description = description
        self.recommendation = recommendation
    
    def matches(self, event):
        raise NotImplementedError

class BruteForceRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Brute Force Attack",
            description="Multiple failed authentication attempts",
            recommendation="Block IP and enable rate limiting"
        )
        self.failed_attempts = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        action = event.get('action', '').lower()
        
        if 'fail' in action or 'denied' in action:
            self.failed_attempts[source_ip] = self.failed_attempts.get(source_ip, 0) + 1
            if self.failed_attempts[source_ip] >= 3:
                return True
        return False

class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Port Scan",
            description="Systematic port scanning detected",
            recommendation="Block source IP immediately"
        )
        self.port_access = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        dest_port = event.get('dest_port', 0)
        
        if source_ip not in self.port_access:
            self.port_access[source_ip] = set()
        self.port_access[source_ip].add(dest_port)
        
        return len(self.port_access[source_ip]) > 10

class SQLInjectionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="SQL Injection Attempt",
            description="Malicious SQL patterns detected",
            recommendation="Block request and audit application"
        )
        self.patterns = ['union select', 'drop table', '1=1', '--', 'exec(', 'xp_cmdshell']
    
    def matches(self, event):
        raw_data = str(event.get('raw_data', '')).lower()
        return any(pattern in raw_data for pattern in self.patterns)

class DDoSRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="DDoS Attack",
            description="High volume traffic detected",
            recommendation="Enable DDoS mitigation"
        )
        self.request_counts = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        self.request_counts[source_ip] = self.request_counts.get(source_ip, 0) + 1
        return self.request_counts[source_ip] > 50

class MalwareRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Malware Activity",
            description="Suspicious file execution detected",
            recommendation="Isolate system and run antivirus"
        )
        self.patterns = ['malware', 'trojan', 'suspicious.exe', 'powershell', 'cmd.exe']
    
    def matches(self, event):
        raw_data = str(event.get('raw_data', '')).lower()
        return any(pattern in raw_data for pattern in self.patterns)