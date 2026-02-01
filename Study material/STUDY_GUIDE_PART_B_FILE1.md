# 🎓 INIDARS COMPLETE STUDY GUIDE
## Part B: Backend Deep Dive (Phase 1)

---

## 4. FILE 1: `feature_extractor.py` - Converting Network Data to Numbers

### 4.1 WHY THIS FILE EXISTS

**Problem**: Machine Learning models can only work with NUMBERS, but network events contain:
- Text: "tcp", "failed", "http"
- IP addresses: "192.168.1.100"
- Mixed data types

**Solution**: This file converts EVERYTHING to numbers between 0 and 1

**Real-world analogy**: Like converting grades to GPA
- "A" → 4.0
- "B" → 3.0
- "C" → 2.0

### 4.2 COMPLETE CODE WALKTHROUGH

```python
"""
Feature Extractor
Converts raw events into numerical feature vectors for ML
"""

class FeatureExtractor:
    def __init__(self):
        pass  # No initialization needed
    
    def extract(self, event):
        """
        Main method: Takes event dict, returns list of 10 numbers
        
        INPUT:  {'source_port': 5000, 'dest_port': 22, 'protocol': 'tcp', ...}
        OUTPUT: [0.076, 0.00034, 0.023, 0.02, 0.3, 0.8, 0.392, 0.196, 0.5, 0.133]
        """
        features = [
            self._normalize_port(event.get('source_port', 0)),      # Feature 0
            self._normalize_port(event.get('dest_port', 0)),        # Feature 1
            self._normalize_bytes(event.get('bytes', 0)),           # Feature 2
            self._normalize_packets(event.get('packets', 0)),       # Feature 3
            self._protocol_to_numeric(event.get('protocol', '')),   # Feature 4
            self._action_to_numeric(event.get('action', '')),       # Feature 5
            self._ip_diversity(event.get('source_ip', '')),         # Feature 6
            self._ip_diversity(event.get('dest_ip', '')),           # Feature 7
            self._time_based_feature(event.get('timestamp', '')),   # Feature 8
            self._payload_size_ratio(event)                         # Feature 9
        ]
        return features
```

**What each feature means**:

| Index | Feature | What it captures |
|-------|---------|-----------------|
| 0 | Source port (normalized) | Client port (usually random 40000-60000) |
| 1 | Destination port (normalized) | Service port (22=SSH, 80=HTTP, etc.) |
| 2 | Bytes transferred | Amount of data sent |
| 3 | Packet count | Number of network packets |
| 4 | Protocol | tcp/udp/http type |
| 5 | Action | allow/deny/failed status |
| 6 | Source IP diversity | How "unusual" source IP is |
| 7 | Dest IP diversity | How "unusual" destination IP is |
| 8 | Time-based | Hour of day (attacks often at night) |
| 9 | Payload ratio | Bytes per packet |

### 4.3 NORMALIZATION METHODS EXPLAINED

#### Method 1: `_normalize_port(port)`
**Purpose**: Convert port number (0-65535) to 0-1 range

```python
def _normalize_port(self, port):
    """
    Normalize port number to 0-1 range
    
    Port range: 0 to 65535
    Formula: port / 65535
    
    Examples:
    - Port 0     → 0.0
    - Port 22    → 0.00034 (SSH)
    - Port 80    → 0.00122 (HTTP)
    - Port 443   → 0.00676 (HTTPS)
    - Port 65535 → 1.0 (max)
    """
    return min(1.0, port / 65535.0)
```

**Why normalize**: ML works better when all features are same scale

#### Method 2: `_normalize_bytes(bytes_val)`
**Purpose**: Convert byte count to 0-1 using logarithmic scale

```python
def _normalize_bytes(self, bytes_val):
    """
    Normalize byte count (log scale)
    
    Problem: Bytes can range from 0 to billions
    - Small request: 100 bytes
    - Large file: 1,000,000,000 bytes
    
    Solution: Use log scale
    
    Formula: log10(bytes + 1) / 10
    
    Examples:
    - 0 bytes      → 0.0
    - 100 bytes    → 0.200    (log10(100) ≈ 2)
    - 1,000 bytes  → 0.300    (log10(1000) = 3)
    - 10,000 bytes → 0.400    (log10(10000) = 4)
    - 1GB          → 0.900    (log10(1B) ≈ 9)
    """
    if bytes_val <= 0:
        return 0
    import math
    return min(1.0, math.log10(bytes_val + 1) / 10.0)
```

**Why log scale**: Compresses huge range into manageable 0-1

#### Method 3: `_protocol_to_numeric(protocol)`
**Purpose**: Convert protocol name to number

```python
def _protocol_to_numeric(self, protocol):
    """
    Convert protocol string to numeric value
    
    Mapping (arbitrary but consistent):
    - tcp:   0.3  (common, reliable)
    - udp:   0.6  (common, fast)
    - icmp:  0.9  (unusual, diagnostic)
    - http:  0.2  (web traffic)
    - https: 0.25 (secure web)
    - ssh:   0.4  (remote access)
    - ftp:   0.5  (file transfer)
    - unknown: 0.0
    
    Why these specific values?
    - Lower values = more common/normal
    - Higher values = less common/more suspicious
    """
    protocol_map = {
        'tcp': 0.3,
        'udp': 0.6,
        'icmp': 0.9,
        'http': 0.2,
        'https': 0.25,
        'ssh': 0.4,
        'ftp': 0.5
    }
    return protocol_map.get(protocol.lower(), 0.0)
```

**Key insight**: Numbers are ordered by "normalcy" (lower = more normal)

#### Method 4: `_action_to_numeric(action)`
**Purpose**: Convert action status to suspicion score

```python
def _action_to_numeric(self, action):
    """
    Convert action to numeric value
    
    Suspicion scale (0 = normal, 1 = suspicious):
    - allow:   0.1  (normal traffic)
    - success: 0.15 (successful action)
    - accept:  0.2  (accepted connection)
    - fail:    0.8  (failed attempt - SUSPICIOUS!)
    - deny:    0.9  (denied access - VERY SUSPICIOUS!)
    - drop:    0.95 (dropped packet - VERY SUSPICIOUS!)
    - reject:  0.85 (rejected - SUSPICIOUS!)
    
    Logic: Failed/denied actions are more suspicious
    """
    action_map = {
        'allow': 0.1,
        'deny': 0.9,
        'drop': 0.95,
        'reject': 0.85,
        'accept': 0.2,
        'fail': 0.8,
        'success': 0.15
    }
    
    action_lower = action.lower()
    for key, value in action_map.items():
        if key in action_lower:  # Substring match
            return value
    
    return 0.5  # neutral if unknown
```

**Why this matters**: Failed logins (action='failed') get 0.8 → triggers ML

#### Method 5: `_ip_diversity(ip)`
**Purpose**: Measure how "unusual" an IP address is

```python
def _ip_diversity(self, ip):
    """
    Measure IP diversity/unusualness
    
    Simple approach: Use last octet
    
    IP format: 192.168.1.X  (X = 0-255)
    Formula: X / 255
    
    Examples:
    - 192.168.1.0   → 0.0
    - 192.168.1.50  → 0.196 (50/255)
    - 192.168.1.100 → 0.392 (100/255)
    - 192.168.1.255 → 1.0
    
    Why last octet?
    - First 3 octets often same within network (192.168.1.X)
    - Last octet varies most
    - Gives diversity measure
    
    Note: This is simplified. Real systems use GeoIP, reputation databases
    """
    if not ip or ip == 'unknown':
        return 0.5
    
    try:
        parts = ip.split('.')  # Split '192.168.1.100' → ['192','168','1','100']
        if len(parts) == 4:
            last_octet = int(parts[-1])  # Get last part
            return last_octet / 255.0
    except:
        pass
    
    return 0.5  # Default if can't parse
```

#### Method 6: `_time_based_feature(timestamp)`
**Purpose**: Extract hour of day (attacks often happen at specific times)

```python
def _time_based_feature(self, timestamp):
    """
    Extract time-based feature (hour of day)
    
    Why? Attacks often correlate with time:
    - Off-hours attacks: 2 AM (suspicious)
    - Business hours: 2 PM (normal)
    
    Formula: hour / 24
    
    Examples:
    - Midnight (0:00)  → 0.0
    - 6 AM             → 0.25
    - Noon (12:00)     → 0.5
    - 6 PM (18:00)     → 0.75
    - 11 PM (23:00)    → 0.958
    
    Timestamp format: '2026-01-31T12:34:56'
    """
    try:
        from datetime import datetime
        if timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour  # Extract hour (0-23)
            return hour / 24.0
    except:
        pass
    
    return 0.5  # Default to noon if can't parse
```

#### Method 7: `_payload_size_ratio(event)`
**Purpose**: Calculate bytes per packet (reveals traffic type)

```python
def _payload_size_ratio(self, event):
    """
    Calculate payload size characteristics
    
    Formula: bytes / packets
    
    Typical packet sizes:
    - Small packets: ~64 bytes (ACK, SYN)
    - Normal packets: ~1500 bytes (MTU limit)
    - Large packets: >1500 bytes (fragmented or unusual)
    
    Examples:
    - 1500 bytes / 1 packet = 1500 → 1.0 (normal)
    - 100 bytes / 10 packets = 10 → 0.007 (small, could be attack)
    - 15000 bytes / 5 packets = 3000 → 1.0 (large, capped at 1.0)
    
    Why useful?
    - DDoS: Many small packets
    - Data exfiltration: Large packets
    - Normal: ~1500 bytes/packet
    """
    bytes_val = event.get('bytes', 0)
    packets = event.get('packets', 1)  # Avoid division by zero
    
    if packets <= 0:
        return 0.5
    
    avg_size = bytes_val / packets
    
    # Normalize (typical packet size ~1500 bytes)
    return min(1.0, avg_size / 1500.0)
```

### 4.4 EXAMPLE END-TO-END

**Input Event**:
```python
event = {
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.50',
    'source_port': 50000,
    'dest_port': 22,
    'protocol': 'tcp',
    'action': 'failed',
    'bytes': 200,
    'packets': 10,
    'timestamp': '2026-01-31T14:30:00'
}
```

**Processing**:
```python
extractor = FeatureExtractor()
features = extractor.extract(event)

# Feature calculation:
features[0] = normalize_port(50000) = 50000/65535 = 0.763
features[1] = normalize_port(22) = 22/65535 = 0.00034
features[2] = normalize_bytes(200) = log10(201)/10 = 0.230
features[3] = normalize_packets(10) = log10(11)/5 = 0.208
features[4] = protocol_to_numeric('tcp') = 0.3
features[5] = action_to_numeric('failed') = 0.8  ← HIGH! Suspicious
features[6] = ip_diversity('192.168.1.100') = 100/255 = 0.392
features[7] = ip_diversity('10.0.0.50') = 50/255 = 0.196
features[8] = time_based('2026-01-31T14:30:00') = 14/24 = 0.583
features[9] = payload_ratio(200, 10) = 20/1500 = 0.013

# Final feature vector:
features = [0.763, 0.00034, 0.230, 0.208, 0.3, 0.8, 0.392, 0.196, 0.583, 0.013]
```

**Output**: List of 10 numbers ready for ML model

### 4.5 WHY THESE 10 FEATURES?

**Network behavior indicators**:
1-2. **Ports**: Reveals service being accessed (SSH, HTTP, etc.)
3-4. **Volume**: How much data (attacks often different volume)
5. **Protocol**: Type of communication
6. **Action**: Success/failure (failed = suspicious)
7-8. **IPs**: Source of traffic
9. **Time**: When it happened
10. **Packet size**: Traffic pattern

**ML insight**: Model learns patterns like:
- "Failed SSH login (port 22, action='failed') from unusual IP at 3 AM → Likely brute force"
- "Many small packets to many ports → Likely port scan"

### 4.6 INTERVIEW QUESTIONS YOU MIGHT GET

**Q: Why normalize to 0-1?**
A: ML models work better when all features are on the same scale. Without normalization:
- Bytes could be 1,000,000
- Port could be 80
- Model would think bytes are more important just because they're bigger numbers

**Q: Why use logarithm for bytes?**
A: Because network traffic sizes vary hugely (100 bytes to 1GB). Log scale compresses this range while preserving the magnitude information. 100 bytes and 200 bytes are closer than 100 bytes and 1GB.

**Q: Can you add more features?**
A: Yes! We could add:
- Packet flags (SYN, ACK, FIN)
- Duration of connection
- Number of connections from same IP
- Payload content analysis
- GeoIP location
NSL-KDD dataset has 41 features!

**Q: What if event is missing data (like port)?**
A: We use `.get(key, default_value)` which returns a default (like 0) if key doesn't exist. Then we normalize 0 normally.

---

**END OF FILE 1**

Ready for File 2 (detector.py)?
