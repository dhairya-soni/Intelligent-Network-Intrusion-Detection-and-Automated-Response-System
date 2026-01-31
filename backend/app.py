"""
INIDARS MVP - Flask Backend - Enhanced with Actions & Better Tracking
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid
from detector import INIDARSDetector
from feature_extractor import FeatureExtractor

app = Flask(__name__)
CORS(app)

# Storage
alerts = []
blocked_ips = set()
action_logs = []
event_counter = 0

# Initialize components - Set use_trained_model=True after running train_model.py
detector = INIDARSDetector(use_trained_model=True)
feature_extractor = FeatureExtractor()

# Severity constants
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

@app.route('/api/events', methods=['POST'])
def ingest_event():
    """Ingest event with IP blocking check"""
    global event_counter
    try:
        event = request.json
        event_counter += 1
        
        source_ip = event.get('source_ip', 'unknown')
        
        # Check if IP is blocked
        if source_ip in blocked_ips:
            log_action('BLOCKED_EVENT', source_ip, f"Event from blocked IP rejected")
            return jsonify({
                'status': 'blocked',
                'message': f'IP {source_ip} is blocked'
            }), 403
        
        # Process through pipeline
        normalized_event = normalize_event(event)
        features = feature_extractor.extract(normalized_event)
        detection_result = detector.detect(features, normalized_event)
        
        if detection_result['is_threat']:
            alert = create_alert(normalized_event, detection_result)
            alerts.append(alert)
            log_action('ALERT_CREATED', source_ip, f"Alert: {detection_result['threat_type']}")
            
            return jsonify({
                'status': 'success',
                'alert_created': True,
                'alert_id': alert['id'],
                'severity': alert['severity'],
                'message': f"Threat detected: {detection_result['threat_type']}"
            }), 201
        
        return jsonify({
            'status': 'success',
            'alert_created': False,
            'message': 'Event processed, no threat detected'
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address"""
    try:
        data = request.json
        ip = data.get('ip')
        reason = data.get('reason', 'Manual block')
        duration = data.get('duration', 'permanent')
        
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        
        blocked_ips.add(ip)
        log_action('IP_BLOCKED', ip, f"Reason: {reason}, Duration: {duration}")
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip} blocked',
            'blocked_at': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    blocked_list = []
    for ip in blocked_ips:
        related_actions = [log for log in action_logs if log['ip'] == ip and 'BLOCK' in log['action']]
        latest_action = related_actions[-1] if related_actions else None
        
        blocked_list.append({
            'ip': ip,
            'blocked_at': latest_action['timestamp'] if latest_action else None,
            'reason': latest_action['details'] if latest_action else 'Unknown',
            'alert_count': sum(1 for a in alerts if a['source_ip'] == ip)
        })
    
    return jsonify(blocked_list)

@app.route('/api/blocked-ips/<ip>', methods=['DELETE'])
def unblock_ip(ip):
    """Unblock an IP"""
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        log_action('IP_UNBLOCKED', ip, 'IP manually unblocked')
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})
    return jsonify({'error': 'IP not found'}), 404

@app.route('/api/ip-history/<ip>', methods=['GET'])
def get_ip_history(ip):
    """Get complete history for an IP"""
    ip_alerts = [a for a in alerts if a['source_ip'] == ip]
    ip_actions = [log for log in action_logs if log['ip'] == ip]
    
    stats = {
        'total_alerts': len(ip_alerts),
        'severity_breakdown': {
            'CRITICAL': sum(1 for a in ip_alerts if a['severity'] == 'CRITICAL'),
            'HIGH': sum(1 for a in ip_alerts if a['severity'] == 'HIGH'),
            'MEDIUM': sum(1 for a in ip_alerts if a['severity'] == 'MEDIUM'),
            'LOW': sum(1 for a in ip_alerts if a['severity'] == 'LOW')
        },
        'threat_types': list(set(a['threat_type'] for a in ip_alerts)),
        'first_seen': min((a['timestamp'] for a in ip_alerts), default=None),
        'last_seen': max((a['timestamp'] for a in ip_alerts), default=None),
        'is_blocked': ip in blocked_ips
    }
    
    return jsonify({
        'ip': ip,
        'statistics': stats,
        'alerts': sorted(ip_alerts, key=lambda x: x['timestamp'], reverse=True),
        'actions': sorted(ip_actions, key=lambda x: x['timestamp'], reverse=True)
    })

@app.route('/api/model/info', methods=['GET'])
def get_model_info():
    """Get ML model information"""
    return jsonify({
        'model': detector.get_model_info(),
        'rules_active': len(detector.rules),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with filtering"""
    severity = request.args.get('severity')
    ip = request.args.get('ip')
    
    filtered = alerts
    if severity:
        filtered = [a for a in filtered if a['severity'] == severity.upper()]
    if ip:
        filtered = [a for a in filtered if ip in a['source_ip']]
    
    return jsonify(sorted(filtered, key=lambda x: x['timestamp'], reverse=True))

@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get specific alert"""
    alert = next((a for a in alerts if a['id'] == alert_id), None)
    if alert:
        return jsonify(alert)
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/alerts/<alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    """Delete specific alert"""
    global alerts
    alerts = [a for a in alerts if a['id'] != alert_id]
    return jsonify({'status': 'success'})

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Enhanced statistics"""
    total_alerts = len(alerts)
    now = datetime.now()
    last_24h = sum(1 for a in alerts if datetime.fromisoformat(a['timestamp']) > now - timedelta(hours=24))
    
    severity_counts = {
        SEVERITY_CRITICAL: sum(1 for a in alerts if a['severity'] == SEVERITY_CRITICAL),
        SEVERITY_HIGH: sum(1 for a in alerts if a['severity'] == SEVERITY_HIGH),
        SEVERITY_MEDIUM: sum(1 for a in alerts if a['severity'] == SEVERITY_MEDIUM),
        SEVERITY_LOW: sum(1 for a in alerts if a['severity'] == SEVERITY_LOW)
    }
    
    attack_types = {}
    for alert in alerts:
        threat = alert.get('threat_type', 'Unknown')
        attack_types[threat] = attack_types.get(threat, 0) + 1
    
    ip_counts = {}
    for alert in alerts:
        ip = alert['source_ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return jsonify({
        'total_events': event_counter,
        'total_alerts': total_alerts,
        'blocked_ips_count': len(blocked_ips),
        'alerts_last_24h': last_24h,
        'severity_counts': severity_counts,
        'attack_types': attack_types,
        'top_offending_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'recent_alerts': sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:5],
        'timestamp': now.isoformat()
    })

@app.route('/api/alerts', methods=['DELETE'])
def clear_alerts():
    """Clear all alerts (for testing)"""
    global alerts, event_counter
    count = len(alerts)
    alerts = []
    event_counter = 0
    log_action('ALERTS_CLEARED', 'system', f'Cleared {count} alerts')
    return jsonify({'status': 'success', 'cleared': count})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'INIDARS MVP',
        'version': '2.0',
        'alerts_count': len(alerts),
        'blocked_ips': len(blocked_ips),
        'total_events': event_counter
    })

def normalize_event(event):
    """Normalize raw event into standard format"""
    return {
        'timestamp': event.get('timestamp', datetime.now().isoformat()),
        'source_ip': event.get('source_ip', 'unknown'),
        'dest_ip': event.get('dest_ip', 'unknown'),
        'source_port': event.get('source_port', 0),
        'dest_port': event.get('dest_port', 0),
        'protocol': event.get('protocol', 'unknown'),
        'action': event.get('action', 'unknown'),
        'bytes': event.get('bytes', 0),
        'packets': event.get('packets', 0),
        'event_type': event.get('event_type', 'network'),
        'raw_data': event
    }

def create_alert(event, detection_result):
    """Create alert from detection result"""
    severity = determine_severity(detection_result)
    
    alert = {
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'severity': severity,
        'threat_type': detection_result['threat_type'],
        'ml_score': round(detection_result['ml_score'], 3),
        'rule_matched': detection_result['rule_matched'],
        'confidence': round(detection_result['confidence'], 2),
        'source_ip': event['source_ip'],
        'dest_ip': event['dest_ip'],
        'dest_port': event['dest_port'],
        'protocol': event['protocol'],
        'description': detection_result['description'],
        'recommendation': detection_result['recommendation'],
        'raw_event': event
    }
    
    return alert

def determine_severity(detection_result):
    """Determine alert severity"""
    score = detection_result['ml_score']
    rule = detection_result['rule_matched']
    
    if score > 0.8 and rule:
        return SEVERITY_CRITICAL
    if (score > 0.65 and rule) or score > 0.85:
        return SEVERITY_HIGH
    if (score > 0.5 and rule) or score > 0.65:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW

def log_action(action, ip, details):
    """Log an action for audit trail"""
    action_logs.append({
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'ip': ip,
        'details': details
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  INIDARS MVP Backend v2.0 Starting...")
    print("=" * 60)
    print("📡 API Server: http://localhost:5000")
    print("🔍 Detection Engine: READY")
    print("📊 Endpoints:")
    print("   - POST /api/events       (Ingest events)")
    print("   - POST /api/block-ip     (Block IP)")
    print("   - GET  /api/blocked-ips  (View blocked)")
    print("   - GET  /api/ip-history   (Investigate IP)")
    print("   - GET  /api/model/info   (ML metrics)")
    print("   - GET  /api/stats        (Statistics)")
    print("=" * 60)
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=True)