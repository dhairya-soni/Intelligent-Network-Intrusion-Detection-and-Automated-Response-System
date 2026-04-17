"""
INIDARS — SQLite persistence layer
Replaces in-memory lists so data survives server restarts.
"""

import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'inidars.db')


# ── Connection helper ─────────────────────────────────────────────────────────
@contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')   # better concurrency
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema initialisation (run once on startup) ───────────────────────────────
def init_db():
    with _db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id              TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                severity        TEXT NOT NULL,
                threat_type     TEXT,
                attack_category TEXT,
                ml_score        REAL,
                rule_matched    INTEGER DEFAULT 0,
                confidence      REAL,
                source_ip       TEXT,
                dest_ip         TEXT,
                dest_port       INTEGER,
                protocol        TEXT,
                description     TEXT,
                recommendation  TEXT,
                explanation     TEXT,   -- JSON blob
                raw_event       TEXT    -- JSON blob
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                reason     TEXT,
                alert_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS action_logs (
                id        TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action    TEXT NOT NULL,
                ip        TEXT,
                details   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_action_logs_ip ON action_logs(ip);

            CREATE TABLE IF NOT EXISTS counters (
                name  TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            );

            INSERT OR IGNORE INTO counters(name, value) VALUES ('event_counter', 0);
        """)
    print(f"Database initialised at {DB_PATH}")


# ── Helpers ───────────────────────────────────────────────────────────────────
def _row_to_alert(row) -> dict:
    d = dict(row)
    for key in ('explanation', 'raw_event'):
        if d.get(key):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    d['rule_matched'] = bool(d.get('rule_matched'))
    return d


# ── Alert CRUD ────────────────────────────────────────────────────────────────
def insert_alert(alert: dict):
    with _db() as conn:
        conn.execute("""
            INSERT INTO alerts
              (id, timestamp, severity, threat_type, attack_category, ml_score,
               rule_matched, confidence, source_ip, dest_ip, dest_port, protocol,
               description, recommendation, explanation, raw_event)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert['id'],
            alert['timestamp'],
            alert['severity'],
            alert.get('threat_type'),
            alert.get('attack_category'),
            alert.get('ml_score'),
            int(bool(alert.get('rule_matched'))),
            alert.get('confidence'),
            alert.get('source_ip'),
            alert.get('dest_ip'),
            alert.get('dest_port'),
            alert.get('protocol'),
            alert.get('description'),
            alert.get('recommendation'),
            json.dumps(alert.get('explanation')) if alert.get('explanation') else None,
            json.dumps(alert.get('raw_event'))   if alert.get('raw_event')   else None,
        ))


def get_alerts(severity: str = None, ip: str = None) -> list[dict]:
    clauses, params = [], []
    if severity:
        clauses.append('severity = ?')
        params.append(severity.upper())
    if ip:
        clauses.append('source_ip LIKE ?')
        params.append(f'%{ip}%')
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with _db() as conn:
        rows = conn.execute(
            f'SELECT * FROM alerts {where} ORDER BY timestamp DESC', params
        ).fetchall()
    return [_row_to_alert(r) for r in rows]


def get_alert(alert_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
    return _row_to_alert(row) if row else None


def delete_alert(alert_id: str) -> bool:
    with _db() as conn:
        c = conn.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
    return c.rowcount > 0


def clear_alerts() -> int:
    with _db() as conn:
        c = conn.execute('DELETE FROM alerts')
    return c.rowcount


def get_alerts_by_ip(ip: str) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            'SELECT * FROM alerts WHERE source_ip = ? ORDER BY timestamp DESC', (ip,)
        ).fetchall()
    return [_row_to_alert(r) for r in rows]


# ── Blocked IPs ───────────────────────────────────────────────────────────────
def block_ip(ip: str, reason: str, blocked_at: str):
    alert_count = len(get_alerts_by_ip(ip))
    with _db() as conn:
        conn.execute("""
            INSERT INTO blocked_ips (ip, blocked_at, reason, alert_count)
            VALUES (?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                blocked_at  = excluded.blocked_at,
                reason      = excluded.reason,
                alert_count = excluded.alert_count
        """, (ip, blocked_at, reason, alert_count))


def unblock_ip(ip: str) -> bool:
    with _db() as conn:
        c = conn.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    return c.rowcount > 0


def is_blocked(ip: str) -> bool:
    with _db() as conn:
        row = conn.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
    return row is not None


def get_blocked_ips() -> list[dict]:
    with _db() as conn:
        rows = conn.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    return [dict(r) for r in rows]


def update_blocked_alert_count(ip: str):
    count = len(get_alerts_by_ip(ip))
    with _db() as conn:
        conn.execute('UPDATE blocked_ips SET alert_count = ? WHERE ip = ?', (count, ip))


# ── Action logs ───────────────────────────────────────────────────────────────
def log_action(action_id: str, timestamp: str, action: str, ip: str, details: str):
    with _db() as conn:
        conn.execute("""
            INSERT INTO action_logs (id, timestamp, action, ip, details)
            VALUES (?,?,?,?,?)
        """, (action_id, timestamp, action, ip, details))


def get_action_logs(ip: str = None, limit: int = 200) -> list[dict]:
    if ip:
        with _db() as conn:
            rows = conn.execute(
                'SELECT * FROM action_logs WHERE ip = ? ORDER BY timestamp DESC LIMIT ?',
                (ip, limit)
            ).fetchall()
    else:
        with _db() as conn:
            rows = conn.execute(
                'SELECT * FROM action_logs ORDER BY timestamp DESC LIMIT ?', (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


# ── Event counter ─────────────────────────────────────────────────────────────
def increment_event_counter() -> int:
    with _db() as conn:
        conn.execute("UPDATE counters SET value = value + 1 WHERE name = 'event_counter'")
        row = conn.execute("SELECT value FROM counters WHERE name = 'event_counter'").fetchone()
    return row['value']


def get_event_counter() -> int:
    with _db() as conn:
        row = conn.execute("SELECT value FROM counters WHERE name = 'event_counter'").fetchone()
    return row['value'] if row else 0


def reset_event_counter():
    with _db() as conn:
        conn.execute("UPDATE counters SET value = 0 WHERE name = 'event_counter'")


# ── Stats helper ──────────────────────────────────────────────────────────────
def get_stats() -> dict:
    with _db() as conn:
        total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        blocked_count = conn.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]

        sev_rows = conn.execute(
            'SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity'
        ).fetchall()
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for r in sev_rows:
            severity_counts[r['severity']] = r['cnt']

        last_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime('now','-24 hours')"
        ).fetchone()[0]

        attack_rows = conn.execute(
            'SELECT threat_type, COUNT(*) as cnt FROM alerts GROUP BY threat_type ORDER BY cnt DESC'
        ).fetchall()
        attack_types = {r['threat_type']: r['cnt'] for r in attack_rows if r['threat_type']}

        top_ip_rows = conn.execute(
            'SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 5'
        ).fetchall()
        top_ips = [{'ip': r['source_ip'], 'count': r['cnt']} for r in top_ip_rows]

        recent_rows = conn.execute(
            'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5'
        ).fetchall()
        recent_alerts = [_row_to_alert(r) for r in recent_rows]

    return {
        'total_alerts':        total_alerts,
        'blocked_ips_count':   blocked_count,
        'alerts_last_24h':     last_24h,
        'severity_counts':     severity_counts,
        'attack_types':        attack_types,
        'top_offending_ips':   top_ips,
        'recent_alerts':       recent_alerts,
    }
