"""
INIDARS Detection Engine
Combines ML-based anomaly detection with rule-based pattern matching
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os

class INIDARSDetector:
    def __init__(self):
        self.ml_model = self._load_or_create_model()
        self.rules = self._initialize_rules()
        
    def _load_or_create_model(self):
        """
        Load pre-trained model or create new one
        """
        model_path = 'model.pkl'
        
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        
        # Create and train basic model
        # In production, this would be trained on real data
        model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Train on dummy data representing normal behavior
        normal_data = np.random.randn(1000, 10)  # 1000 normal samples, 10 features
        model.fit(normal_data)
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        return model
    
    def _initialize_rules(self):
        """
        Initialize detection rules
        """
        return [
            BruteForceRule(),
            PortScanRule(),
            SQLInjectionRule(),
            DDoSRule(),
            MalwareRule()
        ]
    
    def detect(self, features, event):
        """
        Main detection method - combines ML and rule-based detection
        
        Args:
            features: Extracted feature vector
            event: Original event data
            
        Returns:
            Detection result with threat info
        """
        # ML-based anomaly detection
        ml_score = self._ml_detect(features)
        
        # Rule-based detection
        rule_result = self._rule_detect(event)
        
        # Combine results
        is_threat = ml_score > 0.6 or rule_result['matched']
        
        if is_threat:
            # Determine threat type
            if rule_result['matched']:
                threat_type = rule_result['rule_name']
                description = rule_result['description']
                recommendation = rule_result['recommendation']
            else:
                threat_type = "Anomalous Behavior"
                description = f"ML model detected unusual pattern (score: {ml_score:.2f})"
                recommendation = "Investigate source IP and recent activity"
            
            # Calculate combined confidence
            confidence = self._calculate_confidence(ml_score, rule_result['matched'])
            
            return {
                'is_threat': True,
                'threat_type': threat_type,
                'ml_score': ml_score,
                'rule_matched': rule_result['matched'],
                'confidence': confidence,
                'description': description,
                'recommendation': recommendation
            }
        
        return {
            'is_threat': False,
            'threat_type': None,
            'ml_score': ml_score,
            'rule_matched': False,
            'confidence': 0,
            'description': 'No threat detected',
            'recommendation': 'Continue monitoring'
        }
    
    def _ml_detect(self, features):
        """
        ML-based anomaly detection using Isolation Forest
        
        Returns:
            Anomaly score (0-1, higher = more anomalous)
        """
        # Reshape features for sklearn
        feature_array = np.array(features).reshape(1, -1)
        
        # Get anomaly score (-1 to 1, where -1 is outlier)
        score = self.ml_model.score_samples(feature_array)[0]
        
        # Convert to 0-1 scale (higher = more anomalous)
        # Isolation Forest scores range from ~-0.5 to 0.5
        # We normalize to 0-1 where 1 = most anomalous
        normalized_score = max(0, min(1, (-score + 0.5)))
        
        return normalized_score
    
    def _rule_detect(self, event):
        """
        Rule-based detection
        
        Returns:
            Rule match result
        """
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
        """
        Calculate overall confidence (0-100%)
        """
        if rule_matched and ml_score > 0.7:
            return 95  # High confidence: both ML and rule agree
        elif rule_matched:
            return 85  # Good confidence: rule match
        elif ml_score > 0.85:
            return 80  # Good confidence: strong ML signal
        elif ml_score > 0.7:
            return 65  # Medium confidence: moderate ML signal
        else:
            return 50  # Low confidence


class DetectionRule:
    """Base class for detection rules"""
    def __init__(self, name, description, recommendation):
        self.name = name
        self.description = description
        self.recommendation = recommendation
    
    def matches(self, event):
        """Override in subclass"""
        raise NotImplementedError


class BruteForceRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Brute Force Attack",
            description="Multiple failed authentication attempts detected from same source",
            recommendation="Block source IP and enable rate limiting"
        )
        # Track failed login attempts per IP
        self.failed_attempts = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        action = event.get('action', '').lower()
        
        # Check for failed login
        if 'fail' in action or 'denied' in action:
            self.failed_attempts[source_ip] = self.failed_attempts.get(source_ip, 0) + 1
            
            # Trigger if more than 3 failed attempts
            if self.failed_attempts[source_ip] >= 3:
                return True
        
        return False


class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Port Scan",
            description="Systematic scanning of multiple ports detected",
            recommendation="Block source IP and investigate scanning pattern"
        )
        self.port_access = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        dest_port = event.get('dest_port', 0)
        
        # Track ports accessed by this IP
        if source_ip not in self.port_access:
            self.port_access[source_ip] = set()
        
        self.port_access[source_ip].add(dest_port)
        
        # Trigger if accessing more than 10 different ports
        if len(self.port_access[source_ip]) > 10:
            return True
        
        return False


class SQLInjectionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="SQL Injection Attempt",
            description="Malicious SQL patterns detected in request",
            recommendation="Block request and audit application for SQL injection vulnerabilities"
        )
        self.sql_patterns = [
            'union select', 'drop table', 'insert into', 
            'delete from', '1=1', 'or 1=1', '--', 
            'exec(', 'execute('
        ]
    
    def matches(self, event):
        # Check raw data for SQL injection patterns
        raw_data = str(event.get('raw_data', '')).lower()
        
        for pattern in self.sql_patterns:
            if pattern in raw_data:
                return True
        
        return False


class DDoSRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="DDoS Attack",
            description="Abnormally high request volume from source",
            recommendation="Enable DDoS mitigation and rate limiting"
        )
        self.request_counts = {}
    
    def matches(self, event):
        source_ip = event.get('source_ip', '')
        
        # Count requests per IP
        self.request_counts[source_ip] = self.request_counts.get(source_ip, 0) + 1
        
        # Trigger if more than 50 requests from same IP
        if self.request_counts[source_ip] > 50:
            return True
        
        return False


class MalwareRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Malware Activity",
            description="Suspicious file or network pattern indicative of malware",
            recommendation="Quarantine system and run antivirus scan"
        )
        self.suspicious_patterns = [
            'malware', 'trojan', 'ransomware', 'backdoor',
            'suspicious.exe', 'cryptominer', 'botnet'
        ]
    
    def matches(self, event):
        raw_data = str(event.get('raw_data', '')).lower()
        
        for pattern in self.suspicious_patterns:
            if pattern in raw_data:
                return True
        
        return False
