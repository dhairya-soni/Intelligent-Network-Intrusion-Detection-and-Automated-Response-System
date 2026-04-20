"""
INIDARS MVP - Flask Backend - Phase 3
SQLite persistence | CSV/PDF export | Email notifications
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid

from detector import INIDARSDetector
from feature_extractor import FeatureExtractor
import database as db
import threat_intel
import notifier

app = Flask(__name__)
CORS(app)

# ── Startup ───────────────────────────────────────────────────────────────────
db.init_db()
detector         = INIDARSDetector(use_trained_model=True)
feature_extractor = FeatureExtractor()

SEVERITY_CRITICAL = 'CRITICAL'
SEVERITY_HIGH     = 'HIGH'
SEVERITY_MEDIUM   = 'MEDIUM'
SEVERITY_LOW      = 'LOW'


# ── Event ingestion ───────────────────────────────────────────────────────────
@app.route('/api/events', methods=['POST'])
def ingest_event():
    try:
        event        = request.json
        source_ip    = event.get('source_ip', 'unknown')
        event_counter = db.increment_event_counter()

        if db.is_blocked(source_ip):
            _log('BLOCKED_EVENT', source_ip, 'Event from blocked IP rejected')
            return jsonify({'status': 'blocked',
                            'message': f'IP {source_ip} is blocked'}), 403

        normalized = _normalize(event)
        # If demo sends pre-computed NSL-KDD features, use them directly so the
        # ensemble model (trained on 41 NSL-KDD features) gets proper input.
        # Without this, feature_extractor produces only 10 basic features which
        # get zero-padded to 41, making ML predictions garbage.
        if '_nslkdd_features' in event:
            features = event['_nslkdd_features']
        else:
            features = feature_extractor.extract(normalized)
        result       = detector.detect(features, normalized)

        if result['is_threat']:
            alert = _make_alert(normalized, result)
            db.insert_alert(alert)
            _log('ALERT_CREATED', source_ip, f"Alert: {result['threat_type']}")

            # Email notification for CRITICAL alerts
            if alert['severity'] == SEVERITY_CRITICAL:
                notifier.send_critical_alert(alert)

            return jsonify({
                'status':        'success',
                'alert_created': True,
                'alert_id':      alert['id'],
                'severity':      alert['severity'],
                'message':       f"Threat detected: {result['threat_type']}",
            }), 201

        return jsonify({'status': 'success', 'alert_created': False,
                        'message': 'No threat detected'}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    ip       = request.args.get('ip')
    return jsonify(db.get_alerts(severity=severity, ip=ip))


@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    alert = db.get_alert(alert_id)
    return jsonify(alert) if alert else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/alerts/<alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    db.delete_alert(alert_id)
    return jsonify({'status': 'success'})


@app.route('/api/alerts', methods=['DELETE'])
def clear_alerts():
    count = db.clear_alerts()
    db.reset_event_counter()
    _log('ALERTS_CLEARED', 'system', f'Cleared {count} alerts')
    return jsonify({'status': 'success', 'cleared': count})


# ── IP blocking ───────────────────────────────────────────────────────────────
@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    data     = request.json
    ip       = data.get('ip')
    reason   = data.get('reason', 'Manual block')
    duration = data.get('duration', 'permanent')
    if not ip:
        return jsonify({'error': 'IP required'}), 400

    now = datetime.now().isoformat()
    db.block_ip(ip, reason, now)
    _log('IP_BLOCKED', ip, f'Reason: {reason}, Duration: {duration}')
    return jsonify({'status': 'success', 'message': f'IP {ip} blocked',
                    'blocked_at': now})


@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    return jsonify(db.get_blocked_ips())


@app.route('/api/blocked-ips/<path:ip>', methods=['DELETE'])
def unblock_ip(ip):
    if db.unblock_ip(ip):
        _log('IP_UNBLOCKED', ip, 'IP manually unblocked')
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})
    return jsonify({'error': 'IP not found'}), 404


# ── IP history / investigation ────────────────────────────────────────────────
@app.route('/api/ip-history/<path:ip>', methods=['GET'])
def get_ip_history(ip):
    ip_alerts  = db.get_alerts_by_ip(ip)
    ip_actions = db.get_action_logs(ip=ip)

    stats = {
        'total_alerts': len(ip_alerts),
        'severity_breakdown': {
            s: sum(1 for a in ip_alerts if a['severity'] == s)
            for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        },
        'threat_types': list({a['threat_type'] for a in ip_alerts if a.get('threat_type')}),
        'first_seen':   min((a['timestamp'] for a in ip_alerts), default=None),
        'last_seen':    max((a['timestamp'] for a in ip_alerts), default=None),
        'is_blocked':   db.is_blocked(ip),
    }
    return jsonify({'ip': ip, 'statistics': stats,
                    'alerts': ip_alerts, 'actions': ip_actions})


# ── Stats ─────────────────────────────────────────────────────────────────────
@app.route('/api/stats', methods=['GET'])
def get_statistics():
    stats = db.get_stats()
    stats['total_events'] = db.get_event_counter()
    stats['timestamp']    = datetime.now().isoformat()
    return jsonify(stats)


# ── Model info ────────────────────────────────────────────────────────────────
@app.route('/api/model/info', methods=['GET'])
def get_model_info():
    return jsonify({
        'model':        detector.get_model_info(),
        'rules_active': len(detector.rules),
        'timestamp':    datetime.now().isoformat(),
    })


# ── Threat intelligence ───────────────────────────────────────────────────────
@app.route('/api/threat-intel/<path:ip>', methods=['GET'])
def get_threat_intel(ip):
    result = threat_intel.check_ip(ip)
    if result is None:
        return jsonify({'error': 'lookup_failed', 'ip': ip}), 503
    return jsonify(result)


@app.route('/api/threat-intel/status', methods=['GET'])
def threat_intel_status():
    return jsonify(threat_intel.get_cache_stats())


# ── Export: CSV ───────────────────────────────────────────────────────────────
@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    import csv, io
    alerts = db.get_alerts(
        severity=request.args.get('severity'),
        ip=request.args.get('ip'),
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'ID', 'Timestamp', 'Severity', 'Threat Type', 'Attack Category',
        'ML Score', 'Confidence', 'Rule Matched', 'Source IP', 'Dest IP',
        'Dest Port', 'Protocol', 'Description', 'Recommendation',
    ])
    for a in alerts:
        writer.writerow([
            a.get('id'), a.get('timestamp'), a.get('severity'),
            a.get('threat_type'), a.get('attack_category'),
            a.get('ml_score'), a.get('confidence'),
            'Yes' if a.get('rule_matched') else 'No',
            a.get('source_ip'), a.get('dest_ip'), a.get('dest_port'),
            a.get('protocol'), a.get('description'), a.get('recommendation'),
        ])
    filename = f"inidars_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )


# ── Export: PDF ───────────────────────────────────────────────────────────────
@app.route('/api/export/pdf', methods=['GET'])
def export_pdf():
    try:
        from fpdf import FPDF
    except ImportError:
        return jsonify({'error': 'fpdf2 not installed',
                        'fix': 'pip install fpdf2'}), 503

    alerts = db.get_alerts()
    stats  = db.get_stats()
    stats['total_events'] = db.get_event_counter()

    pdf = _build_pdf(alerts, stats)
    filename = f"inidars_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        pdf,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )


def _build_pdf(alerts, stats):
    from fpdf import FPDF

    SEV_COLORS = {
        'CRITICAL': (220, 38,  38),
        'HIGH':     (234, 88,  12),
        'MEDIUM':   (202, 138,  4),
        'LOW':      ( 22, 163, 74),
    }

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Header ────────────────────────────────────────────────────────────────
    pdf.set_fill_color(10, 14, 31)
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_font('Helvetica', 'B', 22)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(10)
    pdf.cell(0, 12, 'INIDARS Security Report', align='C', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 8,
             f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
             f"Intelligent Network Intrusion Detection & Automated Response System",
             align='C', ln=True)
    pdf.set_y(48)

    # ── Executive summary ─────────────────────────────────────────────────────
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Executive Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.ln(2)

    summary_items = [
        ('Total Events Processed', f"{stats.get('total_events', 0):,}"),
        ('Total Alerts Generated', f"{stats.get('total_alerts', 0):,}"),
        ('Blocked IPs',            f"{stats.get('blocked_ips_count', 0):,}"),
        ('Alerts (Last 24h)',      f"{stats.get('alerts_last_24h', 0):,}"),
        ('Critical Alerts',        f"{stats.get('severity_counts', {}).get('CRITICAL', 0):,}"),
        ('High Alerts',            f"{stats.get('severity_counts', {}).get('HIGH', 0):,}"),
    ]

    col_w = 90
    for i, (label, value) in enumerate(summary_items):
        x_off = 10 + (i % 2) * col_w
        if i % 2 == 0:
            pdf.set_x(x_off)
        pdf.set_fill_color(245, 247, 250)
        pdf.set_x(x_off)
        pdf.cell(col_w - 5, 9, f"  {label}: {value}", border=0, ln=(1 if i % 2 else 0), fill=True)
    pdf.ln(6)

    # ── Severity breakdown ────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Severity Breakdown', ln=True)
    pdf.ln(2)
    sev_counts = stats.get('severity_counts', {})
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        cnt = sev_counts.get(sev, 0)
        r, g, b = SEV_COLORS.get(sev, (100, 100, 100))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(28, 7, f' {sev}', fill=True)
        pdf.set_fill_color(245, 247, 250)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(20, 7, str(cnt), fill=True, align='C')
        pdf.ln()
    pdf.ln(6)

    # ── Top offending IPs ─────────────────────────────────────────────────────
    top_ips = stats.get('top_offending_ips', [])
    if top_ips:
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, 'Top Offending IPs', ln=True)
        pdf.ln(2)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(100, 7, '  IP Address', fill=True)
        pdf.cell(40, 7, 'Alert Count', fill=True, align='C')
        pdf.ln()
        for entry in top_ips[:5]:
            pdf.set_fill_color(245, 247, 250)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(100, 6, f"  {entry['ip']}", fill=True)
            pdf.cell(40, 6, str(entry['count']), fill=True, align='C')
            pdf.ln()
        pdf.ln(6)

    # ── Alerts table ──────────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, f'Alert Details (showing up to 50 of {len(alerts)})', ln=True)
    pdf.ln(2)

    headers = ['Severity', 'Threat Type', 'Source IP', 'Category', 'ML%', 'Time']
    widths  = [22, 55, 35, 25, 15, 38]

    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 8)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, f' {h}', fill=True)
    pdf.ln()

    pdf.set_font('Helvetica', '', 8)
    for i, alert in enumerate(alerts[:50]):
        sev = alert.get('severity', 'LOW')
        r, g, b = SEV_COLORS.get(sev, (100, 100, 100))
        if i % 2 == 0:
            pdf.set_fill_color(248, 250, 252)
        else:
            pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(r, g, b)
        pdf.cell(widths[0], 6, f' {sev}', fill=True)
        pdf.set_text_color(30, 30, 30)
        threat = (alert.get('threat_type') or '')[:28]
        pdf.cell(widths[1], 6, f' {threat}', fill=True)
        pdf.cell(widths[2], 6, f" {alert.get('source_ip', '')}", fill=True)
        cat = (alert.get('attack_category') or '')[:12]
        pdf.cell(widths[3], 6, f' {cat}', fill=True)
        ml = int((alert.get('ml_score') or 0) * 100)
        pdf.cell(widths[4], 6, f' {ml}%', fill=True)
        ts = (alert.get('timestamp') or '')[:16].replace('T', ' ')
        pdf.cell(widths[5], 6, f' {ts}', fill=True)
        pdf.ln()

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.set_y(-20)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, 'INIDARS — Intelligent Network Intrusion Detection & Automated Response System',
             align='C', ln=True)

    return pdf.output()


# ── Benchmarks (research paper comparison) ────────────────────────────────────
@app.route('/api/benchmarks', methods=['GET'])
def get_benchmarks():
    published_papers = [
        {
            'id': 'tavallaee2009', 'paper': 'Tavallaee et al. (2009)',
            'title': 'A Detailed Analysis of the KDD CUP 99 Data Set',
            'venue': 'IEEE CISDA', 'method': 'Decision Tree (C4.5)', 'year': 2009,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 99.10, 'precision': 99.30, 'recall': 98.90, 'f1': 99.10,
        },
        {
            'id': 'yin2017', 'paper': 'Yin et al. (2017)',
            'title': 'A Deep Learning Approach for Intrusion Detection Using RNN',
            'venue': 'IEEE Access', 'method': 'LSTM (RNN)', 'year': 2017,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 83.28, 'precision': 82.97, 'recall': 83.28, 'f1': 81.40,
        },
        {
            'id': 'javaid2016', 'paper': 'Javaid et al. (2016)',
            'title': 'A Deep Learning Approach for Network IDS',
            'venue': 'BICT', 'method': 'Sparse Autoencoder + Softmax', 'year': 2016,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 88.39, 'precision': 88.50, 'recall': 88.39, 'f1': 87.96,
        },
        {
            'id': 'kiran2021', 'paper': 'Kiran et al. (2021)',
            'title': 'Hybrid Intrusion Detection Using Machine Learning',
            'venue': 'Applied Sciences', 'method': 'Random Forest (tuned)', 'year': 2021,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 99.10, 'precision': 99.20, 'recall': 99.00, 'f1': 99.10,
        },
        {
            'id': 'li2020', 'paper': 'Li et al. (2020)',
            'title': 'Robust Detection of DoS Attacks via CNN',
            'venue': 'IEEE Trans. IFS', 'method': 'Convolutional Neural Network', 'year': 2020,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 97.50, 'precision': 97.60, 'recall': 97.40, 'f1': 97.30,
        },
        {
            'id': 'ahmad2021', 'paper': 'Ahmad et al. (2021)',
            'title': 'Network IDS with Machine Learning Algorithms',
            'venue': 'Computers & Security', 'method': 'SVM (RBF kernel)', 'year': 2021,
            'dataset': 'NSL-KDD', 'task': 'Binary',
            'accuracy': 93.47, 'precision': 94.10, 'recall': 92.80, 'f1': 93.44,
        },
    ]

    model_info = detector.get_model_info()
    raw        = model_info.get('raw', {})
    binary     = raw.get('binary', {})
    multiclass = raw.get('multiclass', {})
    per_class  = raw.get('per_class', {})
    individual = raw.get('individual', {})

    pkg = detector.model_package or {}
    mh  = pkg.get('metrics_holdout', {})
    bh  = mh.get('binary', {})
    mch = mh.get('multiclass', {})

    def pct(v): return round(v * 100, 2) if v else None

    # Global feature importance from RF
    rf_model = pkg.get('estimators', {}).get('rf') if pkg else None
    feature_importance = []
    if rf_model and hasattr(rf_model, 'feature_importances_'):
        feat_cols = pkg.get('feature_cols', [])
        feature_importance = sorted(
            [{'feature': c, 'importance': round(float(v), 5)}
             for c, v in zip(feat_cols, rf_model.feature_importances_)],
            key=lambda x: x['importance'], reverse=True,
        )[:15]

    our_model = {
        'id': 'inidars', 'paper': 'INIDARS (Ours)',
        'title': 'Intelligent Network Intrusion Detection & Automated Response System',
        'venue': 'This Work', 'method': model_info.get('type', 'Ensemble'),
        'year': 2026, 'dataset': 'NSL-KDD', 'task': 'Binary + Multi-class',
        # Official KDDTest+
        'accuracy':  pct(binary.get('accuracy')),  'precision': pct(binary.get('precision')),
        'recall':    pct(binary.get('recall')),     'f1':        pct(binary.get('f1')),
        'multiclass_accuracy': pct(multiclass.get('accuracy')),
        'multiclass_f1':       pct(multiclass.get('f1')),
        'per_class': per_class,
        # Same-distribution holdout
        'holdout_accuracy':  pct(bh.get('accuracy')),  'holdout_precision': pct(bh.get('precision')),
        'holdout_recall':    pct(bh.get('recall')),     'holdout_f1':        pct(bh.get('f1')),
        'holdout_multiclass_accuracy': pct(mch.get('accuracy')),
        'holdout_multiclass_f1':       pct(mch.get('f1')),
        'individual_models': {
            name: {k: round(v * 100, 2) for k, v in m.items()}
            for name, m in individual.items()
        },
        'feature_importance': feature_importance,
        'is_ours': True,
    }

    return jsonify({
        'our_model':        our_model,
        'published_papers': published_papers,
        'dataset_info': {
            'name': 'NSL-KDD', 'training_samples': '125,973',
            'test_samples': '22,544',
            'classes': ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
            'source': 'University of New Brunswick', 'year': 2009,
        },
        'timestamp': datetime.now().isoformat(),
    })


# ── Health check ──────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health_check():
    stats = db.get_stats()
    return jsonify({
        'status':       'healthy',
        'service':      'INIDARS',
        'version':      '3.0',
        'alerts_count': stats['total_alerts'],
        'blocked_ips':  stats['blocked_ips_count'],
        'total_events': db.get_event_counter(),
        'db':           'SQLite (persistent)',
    })


# ── Internal helpers ──────────────────────────────────────────────────────────
def _normalize(event: dict) -> dict:
    return {
        'timestamp':  event.get('timestamp', datetime.now().isoformat()),
        'source_ip':  event.get('source_ip', 'unknown'),
        'dest_ip':    event.get('dest_ip', 'unknown'),
        'source_port': event.get('source_port', 0),
        'dest_port':  event.get('dest_port', 0),
        'protocol':   event.get('protocol', 'unknown'),
        'action':     event.get('action', 'unknown'),
        'bytes':      event.get('bytes', 0),
        'packets':    event.get('packets', 0),
        'event_type': event.get('event_type', 'network'),
        'raw_data':   event,
    }


def _make_alert(event: dict, result: dict) -> dict:
    sev = _severity(result)
    return {
        'id':               str(uuid.uuid4()),
        'timestamp':        datetime.now().isoformat(),
        'severity':         sev,
        'threat_type':      result['threat_type'],
        'attack_category':  result.get('attack_category', 'Unknown'),
        'ml_score':         round(result['ml_score'], 3),
        'rule_matched':     result['rule_matched'],
        'confidence':       round(result['confidence'], 2),
        'source_ip':        event['source_ip'],
        'dest_ip':          event['dest_ip'],
        'dest_port':        event['dest_port'],
        'protocol':         event['protocol'],
        'description':      result['description'],
        'recommendation':   result['recommendation'],
        'explanation':      result.get('explanation'),
        'raw_event':        event,
    }


def _severity(result: dict) -> str:
    score    = result['ml_score']
    rule     = result['rule_matched']
    category = result.get('attack_category', '')

    # U2R (privilege escalation) is always CRITICAL — highest risk
    if category == 'U2R':
        return SEVERITY_CRITICAL
    # R2L + detected confidently, or very high ML + rule confirms → CRITICAL
    if (category == 'R2L' and score > 0.6) or (score > 0.8 and rule):
        return SEVERITY_CRITICAL
    # DoS / high-confidence ML → HIGH
    if category == 'DoS' or score > 0.7:
        return SEVERITY_HIGH
    # Rule triggered or solid ML confidence → HIGH
    if rule or score > 0.5:
        return SEVERITY_HIGH
    # Probe / moderate ML → MEDIUM
    if category == 'Probe' or score > 0.35:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _log(action: str, ip: str, details: str):
    db.log_action(str(uuid.uuid4()), datetime.now().isoformat(), action, ip, details)


if __name__ == '__main__':
    print("=" * 60)
    print("INIDARS Backend v3.0")
    print("  SQLite persistence: ON")
    print(f"  DB path: {db.DB_PATH}")
    print("  API: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
