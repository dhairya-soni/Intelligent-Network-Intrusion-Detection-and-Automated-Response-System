# 🎓 INIDARS COMPLETE STUDY GUIDE
## Part B: Backend Deep Dive - FILE 2

---

## 5. FILE 2: `detector.py` - Detection Engine (ML + Rules)

### 5.1 WHY THIS FILE EXISTS

**Problem**: How do we know if network traffic is an attack?
- Can't manually check millions of events
- Attacks evolve (new patterns constantly)
- Need both automated (ML) and expert knowledge (rules)

**Solution**: Hybrid detection system
- **ML (Isolation Forest)**: Finds unusual patterns (unsupervised)
- **Rules**: Catches known attack signatures (supervised)
- **Combined**: ML finds new attacks, Rules catch known attacks

**Real-world analogy**: 
- **Rules** = Police wanted posters (known criminals)
- **ML** = Suspicious behavior detection (unknown threats)
- **Both together** = Comprehensive security

### 5.2 FILE STRUCTURE OVERVIEW

```python
detector.py
│
├── INIDARSDetector (Main class)
│   ├── __init__() - Initialize ML model and rules
│   ├── detect() - Main detection method (combines ML + Rules)
│   ├── _ml_detect() - ML anomaly detection
│   ├── _rule_detect() - Rule-based detection
│   └── _calculate_confidence() - Combine scores
│
├── DetectionRule (Base class for rules)
│   └── matches() - Override in subclasses
│
└── 5 Rule Classes
    ├── BruteForceRule
    ├── PortScanRule
    ├── SQLInjectionRule
    ├── DDoSRule
    └── MalwareRule
```

### 5.3 MAIN DETECTOR CLASS - COMPLETE WALKTHROUGH

#### Part 1: Initialization

```python
import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os

class INIDARSDetector:
    def __init__(self, use_trained_model=True):
        """
        Initialize detector with ML model and rules
        
        Args:
            use_trained_model (bool): 
                - True: Use NSL-KDD trained model (76.74% accuracy)
                - False: Use dummy Isolation Forest
        """
        # Load or create ML model
        self.ml_model = self._load_or_create_model(use_trained_model)
        
        # Initialize detection rules (5 rules)
        self.rules = self._initialize_rules()
        
        print(f"🔍 Detector initialized with {'trained' if use_trained_model else 'dummy'} model")
```

**What happens**:
1. Loads ML model (either trained NSL-KDD or simple Isolation Forest)
2. Creates 5 rule objects
3. Ready to detect threats

#### Part 2: Model Loading

```python
def _load_or_create_model(self, use_trained):
    """
    Load ML model from disk or create new one
    
    Two paths:
    1. use_trained=True: Load 'nsl_kdd_model.pkl' (trained on real data)
    2. use_trained=False: Create simple Isolation Forest
    
    Returns:
        Trained ML model
    """
    if use_trained:
        # Path 1: Load trained model
        model_path = 'nsl_kdd_model.pkl'
        
        if os.path.exists(model_path):
            print(f"📂 Loading trained model from {model_path}")
            with open(model_path, 'rb') as f:
                return pickle.load(f)  # Deserialize model
        else:
            print(f"⚠️ Trained model not found! Run train_model.py first")
            print(f"   Falling back to dummy model...")
            use_trained = False  # Fall through to dummy model
    
    if not use_trained:
        # Path 2: Create dummy Isolation Forest
        print("🔨 Creating dummy Isolation Forest model")
        
        model = IsolationForest(
            contamination=0.15,  # Expect 15% of data to be anomalies
            random_state=42,     # Seed for reproducibility
            n_estimators=100     # Number of trees
        )
        
        # Train on random normal data (just for initialization)
        normal_data = np.random.randn(1000, 10)  # 1000 samples, 10 features
        model.fit(normal_data)
        
        # Save for future use
        with open('model.pkl', 'wb') as f:
            pickle.dump(model, f)
        
        return model
```

**Key ML concepts**:

**Isolation Forest**:
- **Type**: Unsupervised anomaly detection
- **How it works**:
  1. Build random decision trees
  2. Anomalies get isolated with fewer splits
  3. Score = average path length (shorter = more anomalous)
  
**contamination=0.15**:
- Assumes 15% of traffic is anomalous
- Affects decision threshold
- Higher = more sensitive (more alerts)

**random_state=42**:
- Ensures reproducible results
- Same training data = same model
- Important for testing/debugging

**pickle**:
- Python serialization library
- Saves Python objects to disk
- `.pkl` file = pickled (saved) model

#### Part 3: Rule Initialization

```python
def _initialize_rules(self):
    """
    Create instances of all detection rules
    
    Returns:
        List of 5 rule objects
    """
    return [
        BruteForceRule(),    # Detects password guessing
        PortScanRule(),      # Detects port scanning
        SQLInjectionRule(),  # Detects SQL injection
        DDoSRule(),          # Detects denial of service
        MalwareRule()        # Detects malware activity
    ]
```

**Why list?**: Easy to iterate and check all rules

#### Part 4: Main Detection Method (THE CORE!)

```python
def detect(self, features, event):
    """
    Main detection method - combines ML and rule-based detection
    
    Args:
        features: List of 10 numbers [0.763, 0.00034, ...]
        event: Original event dict {'source_ip': '192.168.1.100', ...}
    
    Returns:
        Detection result dict:
        {
            'is_threat': True/False,
            'threat_type': 'Brute Force Attack',
            'ml_score': 0.75,
            'rule_matched': True,
            'confidence': 85,
            'description': '...',
            'recommendation': '...'
        }
    """
    
    # STEP 1: ML-based anomaly detection
    ml_score = self._ml_detect(features)
    # Returns: 0.0 - 1.0 (higher = more anomalous)
    # Example: 0.75 means 75% confident it's anomalous
    
    # STEP 2: Rule-based detection
    rule_result = self._rule_detect(event)
    # Returns: {'matched': True/False, 'rule_name': 'Brute Force', ...}
    
    # STEP 3: Combined decision
    is_threat = ml_score > 0.45 or rule_result['matched']
    
    # Threshold explanation:
    # - 0.45 is chosen through experimentation
    # - Lower = more sensitive (more alerts, more false positives)
    # - Higher = less sensitive (fewer alerts, might miss attacks)
    # - OR rule_matched: If rule triggers, always alert (high confidence)
    
    if is_threat:
        # STEP 4: Determine threat type
        if rule_result['matched']:
            # Rule caught it - use rule's info
            threat_type = rule_result['rule_name']
            description = rule_result['description']
            recommendation = rule_result['recommendation']
        else:
            # ML caught it - generic anomaly
            threat_type = "Anomalous Behavior"
            description = f"ML model detected unusual pattern (score: {ml_score:.2f})"
            recommendation = "Investigate source IP and recent activity"
        
        # STEP 5: Calculate combined confidence
        confidence = self._calculate_confidence(ml_score, rule_result['matched'])
        
        # STEP 6: Return threat result
        return {
            'is_threat': True,
            'threat_type': threat_type,
            'ml_score': ml_score,
            'rule_matched': rule_result['matched'],
            'confidence': confidence,
            'description': description,
            'recommendation': recommendation
        }
    
    # No threat detected
    return {
        'is_threat': False,
        'threat_type': None,
        'ml_score': ml_score,
        'rule_matched': False,
        'confidence': 0,
        'description': 'No threat detected',
        'recommendation': 'Continue monitoring'
    }
```

**Decision Logic Diagram**:
```
            ┌─────────────┐
            │   Event     │
            └──────┬──────┘
                   │
        ┌──────────┴──────────┐
        │                     │
    ┌───▼────┐          ┌─────▼──────┐
    │   ML   │          │   Rules    │
    │ Score  │          │  Matched?  │
    └───┬────┘          └─────┬──────┘
        │                     │
     0.75 (75%)           TRUE (Brute Force)
        │                     │
        └──────────┬──────────┘
                   │
              Is Threat?
         (score > 0.45 OR rule)
                   │
                  YES
                   │
         ┌─────────▼─────────┐
         │  Severity = HIGH  │
         │  Confidence = 85  │
         └───────────────────┘
```

#### Part 5: ML Detection Method

```python
def _ml_detect(self, features):
    """
    ML-based anomaly detection using Isolation Forest
    
    Args:
        features: [0.763, 0.00034, 0.230, ...]
    
    Returns:
        Anomaly score (0.0 - 1.0)
        - 0.0 = Very normal
        - 0.5 = Neutral
        - 1.0 = Very anomalous
    """
    
    # Convert list to numpy array (ML requirement)
    feature_array = np.array(features).reshape(1, -1)
    # reshape(1, -1) means: 1 row, any number of columns
    # [0.1, 0.2, 0.3] → [[0.1, 0.2, 0.3]]
    
    # Get anomaly score from model
    score = self.ml_model.score_samples(feature_array)[0]
    
    # Isolation Forest returns NEGATIVE values:
    # - More negative = more anomalous
    # - Less negative = more normal
    # Typical range: -0.5 to 0.5
    
    # Example scores:
    # Normal traffic:    score = 0.4  (close to 0)
    # Slightly odd:      score = 0.1
    # Anomalous:         score = -0.2
    # Very anomalous:    score = -0.5
    
    # Normalize to 0-1 range (higher = more anomalous)
    normalized_score = max(0, min(1, (-score + 0.3)))
    
    # Normalization formula explained:
    # 1. Negate: -score (makes positive)
    # 2. Shift: +0.3 (adjust center)
    # 3. Clip: max(0, min(1, ...)) (force 0-1 range)
    
    # Mapping examples:
    # score = 0.4   → -0.4 + 0.3 = -0.1 → clip to 0.0 (normal)
    # score = 0.0   → -0.0 + 0.3 = 0.3  → 0.3 (neutral)
    # score = -0.2  → -(-0.2) + 0.3 = 0.5 → 0.5 (suspicious)
    # score = -0.5  → -(-0.5) + 0.3 = 0.8 → 0.8 (anomalous)
    # score = -0.8  → -(-0.8) + 0.3 = 1.1 → clip to 1.0 (very anomalous)
    
    # Add small random variation (simulate model uncertainty)
    # In production, remove this
    normalized_score += np.random.uniform(-0.05, 0.05)
    normalized_score = max(0, min(1, normalized_score))
    
    return normalized_score
```

**Why reshape?**: Sklearn expects 2D array (rows × columns)
**Why negative scores?**: Isolation Forest convention (longer path = more negative)

#### Part 6: Rule Detection Method

```python
def _rule_detect(self, event):
    """
    Rule-based detection - check all rules
    
    Args:
        event: {'source_ip': '192.168.1.100', 'action': 'failed', ...}
    
    Returns:
        {
            'matched': True/False,
            'rule_name': 'Brute Force Attack',
            'description': '...',
            'recommendation': '...'
        }
    """
    
    # Check each rule in order
    for rule in self.rules:
        if rule.matches(event):
            # First matching rule wins
            return {
                'matched': True,
                'rule_name': rule.name,
                'description': rule.description,
                'recommendation': rule.recommendation
            }
    
    # No rules matched
    return {
        'matched': False,
        'rule_name': None,
        'description': None,
        'recommendation': None
    }
```

**Logic**: Linear search through rules, return first match

#### Part 7: Confidence Calculation

```python
def _calculate_confidence(self, ml_score, rule_matched):
    """
    Calculate overall confidence (0-100%)
    
    Combines ML score and rule match to determine confidence level
    
    Logic:
    - Both ML and rule agree (high score + rule) = Very high confidence
    - Only rule matches = High confidence (rules are trusted)
    - Only high ML score = Good confidence
    - Low ML score = Low confidence
    
    Args:
        ml_score: 0.0 - 1.0
        rule_matched: True/False
    
    Returns:
        Confidence percentage (0-100)
    """
    
    if rule_matched and ml_score > 0.75:
        return 95  # Very high: Both agree strongly
    elif rule_matched and ml_score > 0.6:
        return 85  # High: Both agree moderately
    elif rule_matched:
        return 75  # Good: Rule matched (trusted)
    elif ml_score > 0.8:
        return 80  # Good: Strong ML signal
    elif ml_score > 0.65:
        return 65  # Moderate: Moderate ML signal
    elif ml_score > 0.5:
        return 55  # Weak: Weak ML signal
    else:
        return 45  # Low: Borderline
```

**Confidence interpretation**:
- 90-100: Almost certain (act immediately)
- 75-89: High confidence (investigate)
- 50-74: Moderate (monitor closely)
- 0-49: Low (log but don't alarm)

### 5.4 DETECTION RULES - DETAILED EXPLANATION

#### Base Rule Class

```python
class DetectionRule:
    """
    Base class for all detection rules
    
    Design pattern: Template Method
    - Base class defines structure
    - Subclasses implement specific logic
    """
    
    def __init__(self, name, description, recommendation):
        """
        Args:
            name: Human-readable rule name
            description: What this rule detects
            recommendation: What to do if detected
        """
        self.name = name
        self.description = description
        self.recommendation = recommendation
    
    def matches(self, event):
        """
        Check if event matches this rule
        
        MUST BE OVERRIDDEN by subclasses
        
        Args:
            event: Event dictionary
        
        Returns:
            True if rule matches, False otherwise
        """
        raise NotImplementedError  # Force subclasses to implement
```

**Design pattern**: Object-oriented programming
- Inheritance: Rules inherit from base class
- Polymorphism: Each rule implements matches() differently

#### Rule 1: Brute Force Detection

```python
class BruteForceRule(DetectionRule):
    """
    Detects brute force attacks (password guessing)
    
    Pattern: Multiple failed login attempts from same IP
    """
    
    def __init__(self):
        super().__init__(  # Call parent constructor
            name="Brute Force Attack",
            description="Multiple failed authentication attempts from same source",
            recommendation="Block source IP and enable rate limiting"
        )
        
        # State tracking (persists between calls)
        self.failed_attempts = {}  # Dictionary: {ip: count}
        # Example: {'192.168.1.100': 5, '10.0.0.1': 2}
    
    def matches(self, event):
        """
        Logic:
        1. Check if action indicates failure
        2. Count failures per IP
        3. Trigger if count >= 3
        
        Returns:
            True if 3+ failed attempts from same IP
        """
        source_ip = event.get('source_ip', '')
        action = event.get('action', '').lower()
        
        # Check for failure keywords
        if 'fail' in action or 'denied' in action:
            # Increment counter for this IP
            self.failed_attempts[source_ip] = self.failed_attempts.get(source_ip, 0) + 1
            
            # Trigger if threshold reached
            if self.failed_attempts[source_ip] >= 3:
                return True  # DETECTED!
        
        return False  # Not detected
```

**How it works**:
```python
# Event 1: Failed login from 192.168.1.100
matches(event1)  # failed_attempts = {'192.168.1.100': 1}  → False

# Event 2: Failed login from 192.168.1.100
matches(event2)  # failed_attempts = {'192.168.1.100': 2}  → False

# Event 3: Failed login from 192.168.1.100
matches(event3)  # failed_attempts = {'192.168.1.100': 3}  → TRUE! Alert!
```

**Limitation**: State resets if backend restarts (in-memory only)
**Production solution**: Use database or Redis for persistence

#### Rule 2: Port Scan Detection

```python
class PortScanRule(DetectionRule):
    """
    Detects port scanning (reconnaissance)
    
    Pattern: Same IP accessing many different ports
    """
    
    def __init__(self):
        super().__init__(
            name="Port Scan",
            description="Systematic scanning of multiple ports from same source",
            recommendation="Block source IP and investigate scanning pattern"
        )
        
        # Track ports accessed per IP
        self.port_access = {}  # {ip: set([22, 23, 80, 443, ...])}
    
    def matches(self, event):
        """
        Logic:
        1. Track which ports each IP accesses
        2. Use set (no duplicates)
        3. Trigger if accessing 10+ unique ports
        """
        source_ip = event.get('source_ip', '')
        dest_port = event.get('dest_port', 0)
        
        # Initialize set for this IP if first time
        if source_ip not in self.port_access:
            self.port_access[source_ip] = set()
        
        # Add port to set (automatically handles duplicates)
        self.port_access[source_ip].add(dest_port)
        
        # Trigger if accessing many ports
        if len(self.port_access[source_ip]) > 10:
            return True  # DETECTED!
        
        return False
```

**Why set?**: Automatically removes duplicates
```python
# Without set:
ports = [22, 22, 23, 22, 80]  # Duplicates
len(ports) = 5  # Wrong count!

# With set:
ports = {22, 22, 23, 22, 80}  # Duplicates removed
len(ports) = 3  # Correct: 3 unique ports
```

**Attack example**:
```
Attacker scans: 20, 21, 22, 23, 24, 25, 80, 443, 3306, 3389, 8080
11 unique ports → DETECTED!
```

#### Rule 3: SQL Injection Detection

```python
class SQLInjectionRule(DetectionRule):
    """
    Detects SQL injection attempts
    
    Pattern: SQL keywords in web requests
    """
    
    def __init__(self):
        super().__init__(
            name="SQL Injection Attempt",
            description="Malicious SQL patterns detected in web request",
            recommendation="Block request and audit application for SQL vulnerabilities"
        )
        
        # Known SQL injection patterns
        self.sql_patterns = [
            'union select',  # Data extraction
            'drop table',    # Data destruction
            'insert into',   # Data manipulation
            'delete from',   # Data deletion
            '1=1',           # Always true condition
            'or 1=1',        # Bypass authentication
            '--',            # SQL comment (hide rest of query)
            'exec(',         # Execute commands
            'execute(',      # Execute commands
            'xp_cmdshell'    # SQL Server command execution
        ]
    
    def matches(self, event):
        """
        Logic:
        1. Get raw request data
        2. Convert to lowercase (case-insensitive)
        3. Check for SQL patterns
        """
        raw_data = str(event.get('raw_data', '')).lower()
        request = str(event.get('request', '')).lower()
        
        # Combine for checking
        combined = raw_data + ' ' + request
        
        # Check each pattern
        for pattern in self.sql_patterns:
            if pattern in combined:
                return True  # DETECTED!
        
        return False
```

**Attack examples**:
```sql
-- Normal request:
http://site.com/user?id=123

-- SQL Injection:
http://site.com/user?id=123 OR 1=1
http://site.com/user?id=123 UNION SELECT password FROM users
http://site.com/user?id=123; DROP TABLE users--
```

**Why lowercase?**: Case-insensitive matching
- "UNION SELECT" and "union select" both detected

#### Rule 4: DDoS Detection

```python
class DDoSRule(DetectionRule):
    """
    Detects Distributed Denial of Service attacks
    
    Pattern: High request volume from single source
    """
    
    def __init__(self):
        super().__init__(
            name="DDoS Attack",
            description="Abnormally high request volume from source",
            recommendation="Enable DDoS mitigation and rate limiting"
        )
        
        # Count requests per IP
        self.request_counts = {}  # {ip: count}
    
    def matches(self, event):
        """
        Logic:
        1. Count requests per IP
        2. Trigger if count > 50
        
        Note: 50 is arbitrary for demo
        Production: Use time windows (requests/second)
        """
        source_ip = event.get('source_ip', '')
        
        # Increment counter
        self.request_counts[source_ip] = self.request_counts.get(source_ip, 0) + 1
        
        # Trigger if high volume
        if self.request_counts[source_ip] > 50:
            return True  # DETECTED!
        
        return False
```

**Limitation**: No time window (counts forever)
**Better approach**: Use sliding time window
```python
# Track timestamps
requests = {
    '192.168.1.1': [time1, time2, time3, ...]
}
# Count only last 60 seconds
recent = [t for t in requests[ip] if now - t < 60]
if len(recent) > 100:  # 100 requests in 1 minute
    return True
```

#### Rule 5: Malware Detection

```python
class MalwareRule(DetectionRule):
    """
    Detects malware activity
    
    Pattern: Suspicious file names, process names, or behaviors
    """
    
    def __init__(self):
        super().__init__(
            name="Malware Activity",
            description="Suspicious file or network pattern indicative of malware",
            recommendation="Isolate system and run antivirus scan"
        )
        
        # Known malware indicators
        self.suspicious_patterns = [
            'malware',       # Explicit malware reference
            'trojan',        # Trojan horse
            'ransomware',    # Ransomware
            'backdoor',      # Backdoor access
            'suspicious.exe',# Suspicious executable
            'cryptominer',   # Cryptocurrency miner
            'botnet',        # Botnet activity
            '.exe',          # Executable file (often suspicious in web traffic)
            'powershell',    # PowerShell (used by many attacks)
            'cmd.exe'        # Command prompt (used by many attacks)
        ]
    
    def matches(self, event):
        """
        Logic:
        1. Check raw data and process name
        2. Look for malware indicators
        """
        raw_data = str(event.get('raw_data', '')).lower()
        process = str(event.get('process', '')).lower()
        
        # Combine for checking
        combined = raw_data + ' ' + process
        
        # Check each pattern
        for pattern in self.suspicious_patterns:
            if pattern in combined:
                return True  # DETECTED!
        
        return False
```

**Limitation**: Simple string matching (high false positives)
**Better approach**: Use hash databases (VirusTotal), behavior analysis

### 5.5 COMPLETE DETECTION FLOW EXAMPLE

**Input Event**:
```python
event = {
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.50',
    'dest_port': 22,
    'protocol': 'tcp',
    'action': 'failed',
    'bytes': 200,
    'packets': 10,
    'timestamp': '2026-01-31T14:30:00'
}
```

**Step-by-step**:

1. **Feature Extraction** (already done):
```python
features = [0.763, 0.00034, 0.230, 0.208, 0.3, 0.8, 0.392, 0.196, 0.583, 0.013]
```

2. **ML Detection**:
```python
ml_score = detector._ml_detect(features)
# Model sees: action feature = 0.8 (failed login)
# Model thinks: "That's unusual! Failed login is suspicious"
# Returns: 0.75 (75% confidence it's anomalous)
```

3. **Rule Detection**:
```python
# BruteForceRule.matches(event):
source_ip = '192.168.1.100'
action = 'failed'  # Contains 'fail'!

failed_attempts['192.168.1.100'] = 3  # (assuming 3rd attempt)
if 3 >= 3:  # TRUE!
    return True  # Brute force detected!

rule_result = {
    'matched': True,
    'rule_name': 'Brute Force Attack',
    'description': 'Multiple failed authentication attempts...',
    'recommendation': 'Block source IP...'
}
```

4. **Combined Decision**:
```python
ml_score = 0.75
rule_matched = True

is_threat = 0.75 > 0.45 or True  # TRUE!
```

5. **Confidence**:
```python
confidence = _calculate_confidence(0.75, True)
# ml_score=0.75, rule_matched=True
# Matches: rule_matched and ml_score > 0.6
# Returns: 85%
```

6. **Final Result**:
```python
{
    'is_threat': True,
    'threat_type': 'Brute Force Attack',
    'ml_score': 0.75,
    'rule_matched': True,
    'confidence': 85,
    'description': 'Multiple failed authentication attempts from same source',
    'recommendation': 'Block source IP and enable rate limiting'
}
```

### 5.6 INTERVIEW QUESTIONS

**Q: Why combine ML and rules?**
A: Defense in depth. ML catches new/unknown attacks, rules catch known patterns with high confidence. Together they cover more threats than either alone.

**Q: What if ML and rules disagree?**
A: We use OR logic (either triggers alert). This makes us more sensitive but might increase false positives. Alternative: Use AND logic for higher precision but might miss attacks.

**Q: How do you prevent false positives?**
A: 
1. Confidence scoring (don't alarm on low confidence)
2. Tunable thresholds (adjust ML threshold based on tolerance)
3. Rule refinement (improve patterns to reduce false matches)
4. User feedback (learn from false positives)

**Q: Why Isolation Forest instead of other ML models?**
A: 
- Unsupervised (doesn't need labeled data for every attack type)
- Fast (good for real-time detection)
- Handles high-dimensional data well
- Good at finding outliers

**Q: Can rules be bypassed?**
A: Yes, attackers can evade rules by:
- Using different patterns
- Slowing down attacks (stay under thresholds)
- Obfuscation (encoding SQL payloads)
This is why we need ML (catches variations)

**Q: How to add a new rule?**
A:
```python
class NewAttackRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="New Attack",
            description="...",
            recommendation="..."
        )
    
    def matches(self, event):
        # Your detection logic
        return True/False

# Add to detector:
def _initialize_rules(self):
    return [
        BruteForceRule(),
        # ... existing rules ...
        NewAttackRule()  # Add here
    ]
```

---

**END OF FILE 2 (detector.py)**

This is the most complex file! Next is app.py (Flask API). Ready to continue?
