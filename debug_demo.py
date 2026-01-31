"""
INIDARS Debug Demo - See what's happening
"""

import requests
import json
from datetime import datetime

API_URL = "http://localhost:5000/api/events"

# Simple test event that SHOULD trigger an alert
test_event = {
    'timestamp': datetime.now().isoformat(),
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.50',
    'source_port': 50000,
    'dest_port': 22,
    'protocol': 'tcp',
    'action': 'failed',  # This should trigger brute force rule
    'bytes': 200,
    'packets': 10,
    'event_type': 'authentication',
    'username': 'admin'
}

print("=" * 70)
print("🔍 INIDARS Debug Test")
print("=" * 70)
print()

# Test 1: Check if backend is running
print("Test 1: Checking backend connection...")
try:
    response = requests.get("http://localhost:5000/health", timeout=2)
    print(f"✓ Backend is running: {response.json()}")
except Exception as e:
    print(f"❌ Backend connection failed: {e}")
    print("Please start the backend first!")
    exit(1)

print()

# Test 2: Send a single test event
print("Test 2: Sending test event...")
print(f"Event data: {json.dumps(test_event, indent=2)}")
print()

try:
    response = requests.post(API_URL, json=test_event, timeout=5)
    result = response.json()
    
    print(f"Response status: {response.status_code}")
    print(f"Response body: {json.dumps(result, indent=2)}")
    print()
    
    if result.get('alert_created'):
        print("✓ Alert was created!")
        print(f"  Severity: {result.get('severity')}")
        print(f"  Alert ID: {result.get('alert_id')}")
    else:
        print("❌ No alert was created")
        print(f"  Message: {result.get('message')}")
        
except Exception as e:
    print(f"❌ Error sending event: {e}")

print()

# Test 3: Check current alerts
print("Test 3: Checking current alerts...")
try:
    response = requests.get("http://localhost:5000/api/alerts", timeout=2)
    alerts = response.json()
    
    print(f"Total alerts in system: {len(alerts)}")
    
    if len(alerts) > 0:
        print("\nLatest alert:")
        latest = alerts[0]
        print(f"  ID: {latest['id']}")
        print(f"  Severity: {latest['severity']}")
        print(f"  Threat: {latest['threat_type']}")
        print(f"  Source IP: {latest['source_ip']}")
        print(f"  ML Score: {latest['ml_score']}")
        print(f"  Rule Matched: {latest['rule_matched']}")
    else:
        print("  No alerts found")
        
except Exception as e:
    print(f"❌ Error getting alerts: {e}")

print()

# Test 4: Send multiple events to trigger rule
print("Test 4: Sending 5 failed login attempts (should trigger brute force)...")
for i in range(5):
    event = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.100',  # Same IP
        'dest_ip': '10.0.0.50',
        'source_port': 50000 + i,
        'dest_port': 22,
        'protocol': 'tcp',
        'action': 'failed',  # Failed login
        'bytes': 200,
        'packets': 10,
        'event_type': 'authentication',
        'username': 'admin'
    }
    
    try:
        response = requests.post(API_URL, json=event, timeout=5)
        result = response.json()
        
        if result.get('alert_created'):
            print(f"  Event {i+1}: ✓ ALERT - {result.get('severity')}")
        else:
            print(f"  Event {i+1}: No alert")
            
    except Exception as e:
        print(f"  Event {i+1}: ERROR - {e}")

print()

# Test 5: Final alert count
print("Test 5: Final alert count...")
try:
    response = requests.get("http://localhost:5000/api/alerts", timeout=2)
    alerts = response.json()
    print(f"Total alerts now: {len(alerts)}")
    
    # Get stats
    response = requests.get("http://localhost:5000/api/stats", timeout=2)
    stats = response.json()
    print(f"\nSeverity breakdown:")
    print(f"  CRITICAL: {stats['severity_counts']['CRITICAL']}")
    print(f"  HIGH:     {stats['severity_counts']['HIGH']}")
    print(f"  MEDIUM:   {stats['severity_counts']['MEDIUM']}")
    print(f"  LOW:      {stats['severity_counts']['LOW']}")
    
except Exception as e:
    print(f"❌ Error: {e}")

print()
print("=" * 70)
print("🌐 Check dashboard at: http://localhost:3000")
print("=" * 70)
