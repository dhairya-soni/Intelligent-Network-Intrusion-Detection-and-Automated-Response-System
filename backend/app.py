"""
INIDARS MVP - Flask Backend - Enhanced Version
Better severity classification for varied alert levels
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import uuid
from detector import INIDARSDetector
from feature_extractor import FeatureExtractor

app = Flask(__name__)
CORS(app)

# In-memory storage
alerts = []
detector = INIDARSDetector()
feature_extractor = FeatureExtractor()

# Alert severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

@app.route('/api/events', methods=['POST'])
def ingest_event():
    """Ingest a security event and process through detection pipeline"""
    try:
        event = request.json
        
        # Step 1: Parse and normalize event
        normalized_event = normalize_event(event)
        
        # Step 2: Extract features
        features = feature_extractor.extract(normalized_event)
        
        # Step 3: Run detection (ML + Rules)
        detection_result = detector.detect(features, normalized_event)
        
        # Step 4: Generate alert if threat detected
        if detection_result['is_threat']:
            alert = create_alert(normalized_event, detection_result)
            alerts.append(alert)
            
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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts, optionally filtered by severity"""
    severity = request.args.get('severity')
    
    if severity:
        filtered = [a for a in alerts if a['severity'] == severity.upper()]
        return jsonify(filtered)
    
    # Return sorted by timestamp (newest first)
    sorted_alerts = sorted(alerts, key=lambda x: x['timestamp'], reverse=True)
    return jsonify(sorted_alerts)

@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get specific alert by ID"""
    alert = next((a for a in alerts if a['id'] == alert_id), None)
    
    if alert:
        return jsonify(alert)
    
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get alert statistics"""
    total = len(alerts)
    
    severity_counts = {
        SEVERITY_CRITICAL: sum(1 for a in alerts if a['severity'] == SEVERITY_CRITICAL),
        SEVERITY_HIGH: sum(1 for a in alerts if a['severity'] == SEVERITY_HIGH),
        SEVERITY_MEDIUM: sum(1 for a in alerts if a['severity'] == SEVERITY_MEDIUM),
        SEVERITY_LOW: sum(1 for a in alerts if a['severity'] == SEVERITY_LOW)
    }
    
    # Attack type distribution
    attack_types = {}
    for alert in alerts:
        threat = alert.get('threat_type', 'Unknown')
        attack_types[threat] = attack_types.get(threat, 0) + 1
    
    # Recent activity (last 10 alerts)
    recent = sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    return jsonify({
        'total_alerts': total,
        'severity_counts': severity_counts,
        'attack_types': attack_types,
        'recent_alerts': recent,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/alerts', methods=['DELETE'])
def clear_alerts():
    """Clear all alerts (for testing)"""
    global alerts
    count = len(alerts)
    alerts = []
    
    return jsonify({
        'status': 'success',
        'message': f'Cleared {count} alerts'
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'INIDARS MVP',
        'alerts_count': len(alerts),
        'timestamp': datetime.now().isoformat()
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
    # Determine severity based on ML score and rule match
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
    """
    Determine alert severity with better distribution
    Updated thresholds for more varied severities
    """
    score = detection_result['ml_score']
    rule = detection_result['rule_matched']
    
    # Critical: Very high ML score + Rule match
    if score > 0.8 and rule:
        return SEVERITY_CRITICAL
    
    # High: High ML score + Rule match OR very high score alone
    if (score > 0.65 and rule) or score > 0.85:
        return SEVERITY_HIGH
    
    # Medium: Moderate ML score + Rule match OR moderate score alone
    if (score > 0.5 and rule) or score > 0.65:
        return SEVERITY_MEDIUM
    
    # Low: Lower ML score OR rule match with low score
    if score > 0.45 or rule:
        return SEVERITY_LOW
    
    # Shouldn't reach here, but default to LOW
    return SEVERITY_LOW

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  INIDARS MVP Backend Starting...")
    print("=" * 60)
    print("📡 API Server: http://localhost:5000")
    print("🔍 Detection Engine: READY (Enhanced)")
    print("📊 Endpoints:")
    print("   - POST /api/events      (Ingest security events)")
    print("   - GET  /api/alerts      (Get all alerts)")
    print("   - GET  /api/stats       (Get statistics)")
    print("   - GET  /health          (Health check)")
    print("=" * 60)
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=True)