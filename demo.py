import requests
import random
import time
from datetime import datetime
import sys

API_URL = "http://localhost:5000/api/events"

def mixed_traffic_generator(i):
    """Logic for the mixed traffic scenario - moved from lambda to fix syntax error"""
    traffic_type = random.choices(
        ['normal', 'suspicious', 'attack'],
        weights=[60, 30, 10],  # 60% normal, 30% suspicious, 10% attack
        k=1
    )[0]
    
    if traffic_type == 'normal':
        return {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'10.0.{random.randint(0, 5)}.{random.randint(1, 254)}',
            'dest_ip': f'10.0.{random.randint(0, 5)}.{random.randint(1, 254)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 25, 53, 3306]),
            'protocol': random.choice(['tcp', 'udp', 'http', 'https']),
            'action': 'allow',
            'bytes': random.randint(100, 5000),
            'packets': random.randint(5, 50),
            'event_type': 'network'
        }
    elif traffic_type == 'suspicious':
        return {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'192.168.{random.randint(1, 10)}.{random.randint(1, 254)}',
            'dest_ip': f'10.0.0.{random.randint(1, 100)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([135, 139, 445, 1433, 3389]),
            'protocol': 'tcp',
            'action': 'allow',
            'bytes': random.randint(500, 3000),
            'packets': random.randint(10, 40),
            'event_type': 'network'
        }
    else:  # attack
        attack_type = random.choice(['brute_force', 'scan', 'sql_injection'])
        if attack_type == 'brute_force':
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': f'192.168.1.{random.randint(100, 120)}',
                'dest_ip': '10.0.0.50',
                'source_port': random.randint(40000, 60000),
                'dest_port': 22,
                'protocol': 'tcp',
                'action': random.choice(['failed', 'denied']),
                'bytes': random.randint(100, 500),
                'packets': random.randint(5, 20),
                'event_type': 'authentication',
                'username': random.choice(['admin', 'root', 'user']),
            }
        elif attack_type == 'scan':
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': f'203.0.113.{random.randint(1, 50)}',
                'dest_ip': '10.0.0.50',
                'source_port': random.randint(40000, 60000),
                'dest_port': random.randint(20, 500),
                'protocol': 'tcp',
                'action': 'allow',
                'bytes': random.randint(50, 100),
                'packets': 1,
                'event_type': 'network'
            }
        else:  # sql_injection
            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': f'198.51.100.{random.randint(1, 50)}',
                'dest_ip': '10.0.0.80',
                'source_port': random.randint(40000, 60000),
                'dest_port': 443,
                'protocol': 'http',
                'action': 'allow',
                'bytes': random.randint(200, 1000),
                'packets': random.randint(10, 30),
                'event_type': 'web',
                'request': '/api/users?id=1 OR 1=1'
            }

# Original Scenario Dictionary Updated
ATTACK_SCENARIOS = {
    'brute_force': {
        'name': 'Brute Force Attack (Mixed Severity)',
        'count': 15,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'192.168.1.{random.randint(100, 120)}',
            'dest_ip': '10.0.0.50',
            'source_port': random.randint(40000, 60000),
            'dest_port': 22,
            'protocol': 'tcp',
            'action': 'failed' if i < 8 else ('denied' if i < 12 else 'suspicious'),
            'bytes': random.randint(100, 500),
            'packets': random.randint(5, 20),
            'event_type': 'authentication',
            'username': random.choice(['admin', 'root', 'user', 'test', 'guest']),
            'password_attempt': f'pass{random.randint(1, 1000)}'
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
            'dest_port': 20 + i,
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
            'source_ip': f'198.51.100.{random.randint(20, 30)}',
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
            'dest_ip': f'185.220.{random.randint(100, 110)}.{random.randint(1, 255)}',
            'source_port': random.randint(40000, 60000),
            'dest_port': random.choice([6667, 8080, 4444]),
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
        'name': 'Normal Traffic (Baseline)',
        'count': 30,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'10.0.0.{random.randint(1, 50)}',
            'dest_ip': f'10.0.0.{random.randint(51, 100)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 3306, 3389, 8080]),
            'protocol': random.choice(['tcp', 'udp', 'http', 'https']),
            'action': random.choice(['allow', 'success', 'accept']),
            'bytes': random.randint(100, 10000),
            'packets': random.randint(5, 100),
            'event_type': random.choice(['network', 'web', 'authentication'])
        }
    },
    'suspicious': {
        'name': 'Suspicious Activity (Medium/Low Severity)',
        'count': 20,
        'generator': lambda i: {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f'172.16.{random.randint(1, 10)}.{random.randint(1, 255)}',
            'dest_ip': f'10.0.0.{random.randint(1, 100)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([21, 23, 135, 445, 1433, 3389]),
            'protocol': random.choice(['tcp', 'udp']),
            'action': 'allow',
            'bytes': random.randint(500, 5000),
            'packets': random.randint(10, 50),
            'event_type': 'network',
            'unusual_pattern': random.choice(['odd_timing', 'unusual_port', 'unexpected_protocol'])
        }
    },
    'mixed_traffic': {
        'name': 'Realistic Mixed Traffic',
        'count': 50,
        'generator': mixed_traffic_generator  # Reference the function here
    }
}

# (The rest of your functions like send_event, run_attack_scenario, and main remain unchanged)
def send_event(event):
    try:
        response = requests.post(API_URL, json=event, timeout=5)
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def run_attack_scenario(scenario_name):
    if scenario_name not in ATTACK_SCENARIOS:
        print(f"❌ Unknown scenario: {scenario_name}")
        return
    
    scenario = ATTACK_SCENARIOS[scenario_name]
    print("=" * 70)
    print(f"🎯 Starting Simulation: {scenario['name']}")
    print(f"📊 Generating {scenario['count']} events...")
    
    alerts_created = 0
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    no_alert_count = 0
    
    for i in range(scenario['count']):
        event = scenario['generator'](i)
        result = send_event(event)
        
        if 'error' in result:
            print(f"❌ Event {i+1:2d}: ERROR - {result['error']}")
        elif result.get('alert_created'):
            alerts_created += 1
            severity = result.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            print(f"{icon} Event {i+1:2d}: ALERT - {severity:8s} - {result.get('message', '')[:50]}")
        else:
            no_alert_count += 1
            print(f"✓ Event {i+1:2d}: Normal traffic")
        
        time.sleep(0.05)
    
    print("\n" + "=" * 70)
    print(f"✅ Simulation Complete!")

def main():
    if len(sys.argv) < 2:
        print("Usage: python demo.py <scenario>")
        return
    
    scenario = sys.argv[1]
    try:
        requests.get("http://localhost:5000/health", timeout=2)
    except:
        print("❌ Error: Backend is not running!")
        return
    
    run_attack_scenario(scenario)

if __name__ == '__main__':
    main()