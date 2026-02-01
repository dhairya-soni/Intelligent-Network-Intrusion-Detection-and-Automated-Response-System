import requests
import random

# Test different traffic types
tests = [
    ('Normal', {'action': 'allow', 'bytes': 1000, 'protocol': 'http', 'dest_port': 80}),
    ('Suspicious', {'action': 'allow', 'bytes': 30000, 'protocol': 'tcp', 'dest_port': 445}),
    ('Brute Force', {'action': 'failed', 'bytes': 200, 'protocol': 'tcp', 'dest_port': 22}),
    ('High Anomaly', {'action': 'denied', 'bytes': 50000, 'protocol': 'icmp', 'dest_port': 0}),
]

for name, overrides in tests:
    event = {
        'timestamp': '2026-02-01T12:00:00',
        'source_ip': f'192.168.1.{random.randint(1,10)}',
        'dest_ip': '10.0.0.1',
        'source_port': random.randint(1000, 65000),
        **overrides
    }
    
    response = requests.post('http://localhost:5000/api/events', json=event)
    result = response.json()
    
    if result.get('alert_created'):
        print(f"{name:15s} -> ML Score: {result.get('ml_score', 0):.3f} -> Severity: {result.get('severity')}")
    else:
        print(f"{name:15s} -> No alert")