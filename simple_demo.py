"""
Simple Working Demo - Generates All Severity Levels
"""

import requests
import time
from datetime import datetime
import random

API_URL = "http://localhost:5000/api/events"

print("=" * 70)
print("🎯 INIDARS Simple Demo - All Severity Levels")
print("=" * 70)
print()

# Check backend
try:
    requests.get("http://localhost:5000/health", timeout=2)
    print("✓ Backend connected")
except:
    print("❌ Backend not running! Start it first.")
    exit(1)

print()
print("Generating 30 events with mixed severities...")
print()

events = []
alerts_created = 0

# Generate varied events
for i in range(30):
    # Vary the event characteristics to get different severities
    
    if i < 5:
        # These should be CRITICAL or HIGH (brute force)
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'192.168.1.{100 + i}',
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
    elif i < 10:
        # These should be HIGH (port scan pattern)
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '203.0.113.45',
            'dest_ip': '10.0.0.50',
            'source_port': 45000,
            'dest_port': 20 + i,  # Different ports
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': 100,
            'packets': 1,
            'event_type': 'network'
        }
    elif i < 15:
        # These should be MEDIUM (suspicious but not clear attack)
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'172.16.{random.randint(1,10)}.{random.randint(1,255)}',
            'dest_ip': '10.0.0.80',
            'source_port': random.randint(40000, 60000),
            'dest_port': random.choice([445, 3389, 1433]),  # Sensitive ports
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': 1000,
            'packets': 20,
            'event_type': 'network'
        }
    elif i < 20:
        # These should be LOW or no alert (borderline)
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'10.0.{random.randint(1,5)}.{random.randint(1,254)}',
            'dest_ip': f'10.0.{random.randint(1,5)}.{random.randint(1,254)}',
            'source_port': random.randint(40000, 60000),
            'dest_port': random.choice([80, 443, 22]),
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': random.randint(500, 2000),
            'packets': random.randint(10, 30),
            'event_type': 'network'
        }
    else:
        # These should be normal (no alert)
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'10.0.0.{random.randint(1,50)}',
            'dest_ip': f'10.0.0.{random.randint(51,100)}',
            'source_port': random.randint(40000, 60000),
            'dest_port': random.choice([80, 443]),
            'protocol': 'https',
            'action': 'allow',
            'bytes': random.randint(100, 1000),
            'packets': random.randint(5, 20),
            'event_type': 'web'
        }
    
    # Send event
    try:
        response = requests.post(API_URL, json=event, timeout=5)
        result = response.json()
        
        if result.get('alert_created'):
            severity = result.get('severity', 'UNKNOWN')
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            print(f"{icon} Event {i+1:2d}: {severity:8s} - {result.get('message', '')[:50]}")
            alerts_created += 1
        else:
            print(f"✓ Event {i+1:2d}: Normal (no alert)")
    
    except Exception as e:
        print(f"❌ Event {i+1:2d}: Error - {e}")
    
    time.sleep(0.05)

print()
print("=" * 70)
print(f"✅ Complete! Created {alerts_created} alerts from 30 events")
print("=" * 70)
print()
print("🌐 Check dashboard: http://localhost:3000")
print("   (Wait 3 seconds for refresh)")
print()
