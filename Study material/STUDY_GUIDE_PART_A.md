# 🎓 INIDARS COMPLETE STUDY GUIDE
## Part A: Foundation Knowledge

---

## 1. TECHNOLOGIES OVERVIEW

### 1.1 Python (Backend Language)
**What it is**: A programming language that's easy to read and write
**Why we use it**: Great for data processing, ML, and building APIs
**In our project**: Runs the backend server, ML models, and detection logic

**Key Python concepts you'll use:**
```python
# Variables - Store data
name = "INIDARS"
count = 10

# Functions - Reusable code blocks
def detect_threat(event):
    # Code here
    return result

# Classes - Blueprint for objects
class Detector:
    def __init__(self):  # Constructor - runs when creating object
        self.model = None
    
    def detect(self, data):
        # Detection logic
        pass

# Lists - Collection of items
alerts = [alert1, alert2, alert3]

# Dictionaries - Key-value pairs (like JSON)
event = {
    'source_ip': '192.168.1.1',
    'dest_port': 80,
    'action': 'allow'
}
```

### 1.2 Flask (Python Web Framework)
**What it is**: A tool to create web APIs (Application Programming Interface)
**Why we use it**: Lets frontend communicate with backend
**In our project**: Creates endpoints like `/api/events`, `/api/alerts`

**How Flask works:**
```python
from flask import Flask, request, jsonify

app = Flask(__name__)  # Create app

# Define an endpoint
@app.route('/api/hello', methods=['GET'])  # Decorator - says "when someone visits /api/hello"
def hello():
    return jsonify({'message': 'Hello World'})  # Return JSON response

# Start server
app.run(port=5000)  # Listen on port 5000
```

**Key Flask concepts:**
- **Route**: A URL path (like `/api/events`)
- **Decorator (@app.route)**: Python syntax to modify functions
- **Methods**: GET (read data), POST (send data), DELETE (remove data)
- **jsonify**: Converts Python dict to JSON format
- **request**: Object containing data sent by client

### 1.3 Machine Learning (scikit-learn)
**What it is**: Teaching computers to find patterns in data
**Why we use it**: Detect abnormal network behavior automatically
**In our project**: Trained on 125,973 network samples to recognize attacks

**Key ML concepts:**

**Supervised Learning**: Training with labeled data
- We have: Network traffic labeled as "normal" or "attack"
- Model learns: Patterns that distinguish attacks from normal traffic
- Result: Can classify new traffic

**Random Forest Classifier**:
- **What**: Collection of decision trees that vote
- **How it works**: 
  1. Create many decision trees (like 100)
  2. Each tree looks at different features
  3. Trees vote on classification
  4. Majority wins
- **Why**: More accurate than single tree, resistant to overfitting

**Isolation Forest** (Anomaly Detection):
- **What**: Finds outliers (unusual data points)
- **How it works**:
  1. Randomly partition data into trees
  2. Unusual points get isolated quickly (fewer splits needed)
  3. Normal points need many splits
  4. Score = how easily isolated (0-1, higher = more anomalous)
- **Why**: Good for unsupervised detection (doesn't need labels)

**Training vs. Prediction**:
```python
# TRAINING (one-time, offline)
model = RandomForestClassifier()
model.fit(X_train, y_train)  # Learn from labeled data
# X_train = features (network data)
# y_train = labels (normal/attack)

# PREDICTION (real-time, online)
prediction = model.predict(new_event)  # Classify new traffic
# Returns: 0 (normal) or 1 (attack)
```

**Key ML terms:**
- **Features**: Input data (like bytes, ports, protocol)
- **Labels**: Output categories (normal/attack)
- **Training**: Learning from data
- **Prediction/Inference**: Using trained model on new data
- **Accuracy**: % of correct predictions
- **Precision**: % of predicted attacks that are real attacks
- **Recall**: % of real attacks that we detected

### 1.4 React (Frontend Framework)
**What it is**: JavaScript library for building user interfaces
**Why we use it**: Creates interactive, dynamic web pages
**In our project**: Dashboard that updates in real-time

**Key React concepts:**

**JSX**: HTML-like syntax in JavaScript
```javascript
// This looks like HTML but it's JavaScript!
const element = <h1>Hello, INIDARS!</h1>
```

**Components**: Reusable UI pieces
```javascript
function Dashboard() {
    return (
        <div>
            <h1>Dashboard</h1>
            <p>Statistics here</p>
        </div>
    )
}
```

**Props**: Passing data to components
```javascript
<Dashboard stats={statsData} />  // Parent passes data
function Dashboard({ stats }) {   // Child receives data
    return <div>{stats.total}</div>
}
```

**State**: Data that can change
```javascript
const [alerts, setAlerts] = useState([])  // Create state variable
setAlerts(newAlerts)  // Update state -> UI re-renders
```

**Hooks**: Special React functions
- `useState`: Add state to component
- `useEffect`: Run code on mount/update (like fetching data)

**Event Handling**:
```javascript
<button onClick={handleClick}>Click me</button>
function handleClick() {
    // Do something
}
```

### 1.5 Tailwind CSS (Styling)
**What it is**: CSS framework with pre-made classes
**Why we use it**: Fast, consistent styling without writing CSS
**Example**:
```html
<div className="bg-blue-500 text-white p-4 rounded">
  <!-- bg-blue-500 = blue background -->
  <!-- text-white = white text -->
  <!-- p-4 = padding -->
  <!-- rounded = rounded corners -->
</div>
```

---

## 2. PROJECT ARCHITECTURE & DATA FLOW

### 2.1 High-Level Architecture

```
┌─────────────────┐
│   USER BROWSER  │  (Opens http://localhost:3000)
└────────┬────────┘
         │
         v
┌─────────────────────────────────────────┐
│        REACT FRONTEND (Port 3000)       │
│  - Dashboard.jsx                        │
│  - AlertsList.jsx                       │
│  - Shows alerts, statistics, graphs     │
└────────┬────────────────────────────────┘
         │ HTTP Requests (via api.js)
         │ GET /api/alerts
         │ POST /api/events
         │ POST /api/block-ip
         v
┌─────────────────────────────────────────┐
│       FLASK BACKEND (Port 5000)         │
│                                         │
│  app.py ─→ Routes HTTP requests        │
│     │                                   │
│     v                                   │
│  detector.py ─→ ML + Rules              │
│     │            │                      │
│     │            v                      │
│     │      feature_extractor.py         │
│     │       (Convert to numbers)        │
│     v                                   │
│  In-Memory Storage                      │
│  - alerts[] list                        │
│  - blocked_ips set                      │
└─────────────────────────────────────────┘
         ^
         │ Demo sends fake events
         │
┌────────┴────────┐
│    demo.py      │  (Simulates attacks)
└─────────────────┘
```

### 2.2 Complete Data Flow (Step-by-Step)

**SCENARIO**: Someone runs `python demo.py brute_force`

**Step 1: Event Generation (demo.py)**
```python
# Create fake network event
event = {
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.50',
    'dest_port': 22,
    'protocol': 'tcp',
    'action': 'failed',  # Failed login
    'bytes': 200,
    'packets': 10
}
# Send to backend
requests.post('http://localhost:5000/api/events', json=event)
```

**Step 2: Backend Receives (app.py)**
```python
@app.route('/api/events', methods=['POST'])
def ingest_event():
    event = request.json  # Get data from request
    # Process it...
```

**Step 3: Feature Extraction (feature_extractor.py)**
```python
# Convert event to numbers ML can understand
features = [
    normalize_port(event['dest_port']),     # 22 -> 0.00034
    normalize_bytes(event['bytes']),        # 200 -> 0.023
    protocol_to_numeric(event['protocol']), # 'tcp' -> 0.3
    action_to_numeric(event['action']),     # 'failed' -> 0.8
    # ... 10 features total
]
# Result: [0.00034, 0.023, 0.3, 0.8, ...]
```

**Step 4: ML Detection (detector.py)**
```python
# A) ML Anomaly Detection
ml_score = model.predict(features)  # Returns 0.0-1.0
# Example: 0.75 (75% confident this is anomalous)

# B) Rule-Based Detection
for rule in rules:
    if rule.matches(event):
        # Example: BruteForceRule checks failed logins
        # If 3+ failed logins from same IP -> MATCHED
        return {'matched': True, 'rule_name': 'Brute Force'}
```

**Step 5: Combined Decision**
```python
if ml_score > 0.45 or rule_matched:
    # It's a threat!
    is_threat = True
    
    # Determine severity
    if ml_score > 0.8 and rule_matched:
        severity = "CRITICAL"
    elif ml_score > 0.65 and rule_matched:
        severity = "HIGH"
    # ... etc
```

**Step 6: Create Alert (app.py)**
```python
alert = {
    'id': 'uuid-123',
    'timestamp': '2026-01-31T12:00:00',
    'severity': 'HIGH',
    'threat_type': 'Brute Force Attack',
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.50',
    'ml_score': 0.75,
    'rule_matched': True,
    'confidence': 85,
    'description': 'Multiple failed logins detected',
    'recommendation': 'Block source IP'
}
alerts.append(alert)  # Store in memory
```

**Step 7: Return Response**
```python
return jsonify({
    'status': 'success',
    'alert_created': True,
    'severity': 'HIGH',
    'alert_id': 'uuid-123'
})
```

**Step 8: Frontend Fetches Alerts (Dashboard.jsx)**
```javascript
// Every 3 seconds, React calls:
const response = await axios.get('/api/alerts')
const alerts = response.data
setAlerts(alerts)  // Update UI
```

**Step 9: User Sees Alert**
```
Dashboard shows:
🟠 HIGH - Brute Force Attack
   192.168.1.100 → 10.0.0.50:22
   ML: 75% | Confidence: 85%
   [Investigate] [Block]
```

**Step 10: User Blocks IP**
```javascript
// User clicks "Block" button
await axios.post('/api/block-ip', { ip: '192.168.1.100' })
```

**Step 11: Backend Blocks IP (app.py)**
```python
@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    ip = request.json['ip']
    blocked_ips.add(ip)  # Add to set
    # Now future events from this IP are rejected
```

---

## 3. KEY CONCEPTS YOU MUST KNOW

### 3.1 Network Security Terms

**IP Address**: Unique identifier for device on network
- Example: `192.168.1.100` (source), `10.0.0.50` (destination)
- Like a phone number for computers

**Port**: Door number on a computer (0-65535)
- Port 22: SSH (remote login)
- Port 80: HTTP (web)
- Port 443: HTTPS (secure web)
- Port 3306: MySQL database

**Protocol**: Rules for communication
- TCP: Reliable, ordered delivery (like certified mail)
- UDP: Fast, no guarantees (like regular mail)
- HTTP: Web traffic
- SSH: Secure remote access

**Network Event**: Any network activity
```json
{
  "source_ip": "192.168.1.100",    // Who sent it
  "dest_ip": "10.0.0.50",          // Who received it
  "dest_port": 22,                 // Which service
  "protocol": "tcp",               // How sent
  "action": "failed",              // What happened
  "bytes": 200,                    // How much data
  "packets": 10                    // How many packets
}
```

### 3.2 Attack Types We Detect

**1. Brute Force Attack**
- **What**: Trying many passwords to guess the right one
- **How we detect**: Count failed login attempts from same IP
- **Rule**: If 3+ failed logins → ALERT
- **Example**: Attacker tries "password123", "admin", "12345"...

**2. Port Scan**
- **What**: Testing which ports are open (reconnaissance)
- **How we detect**: Count unique ports accessed from same IP
- **Rule**: If 10+ different ports → ALERT
- **Example**: Attacker probes ports 20, 21, 22, 23...

**3. SQL Injection**
- **What**: Inserting malicious SQL code into web forms
- **How we detect**: Look for SQL keywords in request
- **Rule**: If contains "OR 1=1", "UNION SELECT", "DROP TABLE" → ALERT
- **Example**: `http://site.com/user?id=1 OR 1=1`

**4. DDoS (Distributed Denial of Service)**
- **What**: Overwhelming server with traffic
- **How we detect**: Count requests from same IP
- **Rule**: If 50+ requests → ALERT
- **Example**: Bot sends 1000 requests/second

**5. Malware Activity**
- **What**: Suspicious file or network behavior
- **How we detect**: Look for malware-related patterns
- **Rule**: If process name contains ".exe", "malware", "trojan" → ALERT
- **Example**: Process "suspicious.exe" connects to external IP

### 3.3 Alert Severity Levels

**CRITICAL** (🔴): Immediate action required
- **When**: High ML score (>0.8) + Rule match
- **Example**: Brute force with 10 failed logins
- **Action**: Block IP immediately

**HIGH** (🟠): Serious threat
- **When**: High ML score (>0.65) + Rule OR Very high ML score (>0.85)
- **Example**: Port scan detected
- **Action**: Investigate and likely block

**MEDIUM** (🟡): Suspicious activity
- **When**: Moderate ML score (>0.5) + Rule OR Moderate score (>0.65)
- **Example**: Unusual traffic pattern
- **Action**: Monitor closely

**LOW** (🟢): Minor anomaly
- **When**: Low ML score (>0.45) OR Rule match with low score
- **Example**: Slightly unusual but not clearly malicious
- **Action**: Log for analysis

### 3.4 Detection Pipeline Explained

```
RAW EVENT → NORMALIZE → EXTRACT FEATURES → ML + RULES → ALERT
```

**1. Normalize**: Convert to standard format
```python
# Before: Various formats
{'src': '192.168.1.1', 'dst': '10.0.0.1'}
{'source': '192.168.1.2', 'destination': '10.0.0.2'}

# After: Consistent format
{'source_ip': '192.168.1.1', 'dest_ip': '10.0.0.1'}
{'source_ip': '192.168.1.2', 'dest_ip': '10.0.0.2'}
```

**2. Extract Features**: Convert to numbers (ML requirement)
```python
# Event (text/numbers mixed)
{'dest_port': 22, 'protocol': 'tcp', 'action': 'failed'}

# Features (all numbers, 0-1 range)
[0.00034, 0.3, 0.8, ...]
```

**3. ML Detection**: Anomaly scoring
```python
score = model.predict([0.00034, 0.3, 0.8, ...])
# Returns: 0.75 (75% confident it's anomalous)
```

**4. Rule Detection**: Pattern matching
```python
if event['action'] == 'failed':
    failed_count += 1
    if failed_count >= 3:
        return True  # Brute force detected!
```

**5. Combine Results**: Final decision
```python
if score > 0.45 or rule_matched:
    create_alert()
```

---

**END OF PART A**

This covers the foundation. Ready for Part B (Backend files)?
