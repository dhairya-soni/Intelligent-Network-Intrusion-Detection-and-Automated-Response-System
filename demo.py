"""
INIDARS Attack Simulator
Generates realistic attack scenarios for demo purposes
"""

import requests
import random
import time
from datetime import datetime
import sys

API_URL = "http://localhost:5000/api/events"

# Attack templates
ATTACK_SCENARIOS = {
    'brute_force': {
        'name': 'Brute Force Attack',
        'count': 10,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'source_port': random.randint(40000, 60000),
            'dest_port': 22,
            'protocol': 'tcp',
            'action': 'failed' if i < 8 else 'denied',
            'bytes': random.randint(100, 500),
            'packets': random.randint(5, 20),
            'event_type': 'authentication',
            'username': f'admin_{i}',
            'password_attempt': f'pass{i}'
        }
    },
    'port_scan': {
        'name': 'Port Scan Attack',
        'count': 15,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '203.0.113.45',
            'dest_ip': '10.0.0.50',
            'source_port': random.randint(40000, 60000),
            'dest_port': 20 + i,  # Sequential ports
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': random.randint(50, 100),
            'packets': 1,
            'event_type': 'network',
            'scan_type': 'SYN'
        }
    },
    'sql_injection': {
        'name': 'SQL Injection Attack',
        'count': 5,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '198.51.100.23',
            'dest_ip': '10.0.0.80',
            'source_port': random.randint(40000, 60000),
            'dest_port': 443,
            'protocol': 'http',
            'action': 'allow',
            'bytes': random.randint(200, 1000),
            'packets': random.randint(10, 30),
            'event_type': 'web',
            'request': f'/api/users?id=1 OR 1=1 UNION SELECT * FROM users--',
            'payload': 'malicious SQL query'
        }
    },
    'ddos': {
        'name': 'DDoS Attack',
        'count': 60,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'203.0.113.{random.randint(1, 255)}',
            'dest_ip': '10.0.0.100',
            'source_port': random.randint(1024, 65535),
            'dest_port': 80,
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': random.randint(100, 500),
            'packets': random.randint(50, 200),
            'event_type': 'network',
            'flood_type': 'SYN'
        }
    },
    'malware': {
        'name': 'Malware Activity',
        'count': 8,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '10.0.0.150',
            'dest_ip': '185.220.101.5',  # Suspicious external IP
            'source_port': random.randint(40000, 60000),
            'dest_port': random.choice([6667, 8080, 4444]),  # Common malware ports
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': random.randint(5000, 50000),
            'packets': random.randint(100, 500),
            'event_type': 'network',
            'process': 'suspicious.exe',
            'file_hash': f'a1b2c3d4e5f6{i}',
            'behavior': 'suspicious outbound connection'
        }
    },
    'normal': {
        'name': 'Normal Traffic',
        'count': 20,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'10.0.0.{random.randint(1, 50)}',
            'dest_ip': f'10.0.0.{random.randint(51, 100)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 3306]),
            'protocol': random.choice(['tcp', 'udp']),
            'action': 'allow',
            'bytes': random.randint(100, 10000),
            'packets': random.randint(5, 100),
            'event_type': 'network'
        }
    }
}

def send_event(event):
    """Send event to INIDARS backend"""
    try:
        response = requests.post(API_URL, json=event, timeout=5)
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def run_attack_scenario(scenario_name):
    """Run a specific attack scenario"""
    if scenario_name not in ATTACK_SCENARIOS:
        print(f"❌ Unknown scenario: {scenario_name}")
        print(f"Available scenarios: {', '.join(ATTACK_SCENARIOS.keys())}")
        return
    
    scenario = ATTACK_SCENARIOS[scenario_name]
    
    print("=" * 60)
    print(f"🎯 Starting Attack Simulation: {scenario['name']}")
    print("=" * 60)
    print(f"📊 Generating {scenario['count']} events...")
    print()
    
    alerts_created = 0
    
    for i in range(scenario['count']):
        event = scenario['generator'](i)
        
        # Send event
        result = send_event(event)
        
        # Print result
        if 'error' in result:
            print(f"❌ Event {i+1}: ERROR - {result['error']}")
        elif result.get('alert_created'):
            alerts_created += 1
            severity = result.get('severity', 'UNKNOWN')
            print(f"🚨 Event {i+1}: ALERT CREATED - {severity} - {result.get('message', '')}")
        else:
            print(f"✓ Event {i+1}: Processed (no threat)")
        
        # Small delay to avoid overwhelming the backend
        time.sleep(0.1)
    
    print()
    print("=" * 60)
    print(f"✅ Simulation Complete!")
    print(f"📊 Events sent: {scenario['count']}")
    print(f"🚨 Alerts created: {alerts_created}")
    print(f"📈 Detection rate: {(alerts_created/scenario['count']*100):.1f}%")
    print("=" * 60)
    print()
    print("🌐 View dashboard at: http://localhost:3000")
    print()

def main():
    if len(sys.argv) < 2:
        print("INIDARS Attack Simulator")
        print()
        print("Usage: python demo.py <scenario>")
        print()
        print("Available scenarios:")
        for name, info in ATTACK_SCENARIOS.items():
            print(f"  - {name:15} : {info['name']}")
        print()
        print("Examples:")
        print("  python demo.py brute_force")
        print("  python demo.py port_scan")
        print("  python demo.py ddos")
        return
    
    scenario = sys.argv[1]
    
    # Check if backend is running
    try:
        requests.get("http://localhost:5000/health", timeout=2)
    except:
        print("❌ Error: Backend is not running!")
        print("Please start the backend first:")
        print("  cd backend")
        print("  python app.py")
        return
    
    run_attack_scenario(scenario)

if __name__ == '__main__':
    main()
