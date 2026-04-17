"""
Threat Intelligence — AbuseIPDB integration
Free API: https://www.abuseipdb.com (register for a free key)
Set env var:  ABUSEIPDB_KEY=your_key_here
"""

import os
import requests
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────────────────────────────
API_KEY   = os.environ.get('ABUSEIPDB_KEY', '')
BASE_URL  = 'https://api.abuseipdb.com/api/v2/check'
CACHE_TTL = 3600   # cache results 1 hour (free tier: 1000 checks/day)

# ── In-memory cache: ip → (data_dict, expiry_datetime) ───────────────────────
_cache: dict = {}

# ── Private IPs that don't need an external lookup ────────────────────────────
_PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                     '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                     '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                     '172.29.', '172.30.', '172.31.', '127.', '::1', 'unknown')


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def check_ip(ip: str) -> dict | None:
    """
    Query AbuseIPDB for reputation data on `ip`.

    Returns a dict with abuse info, or None if:
    - No API key configured
    - IP is private/loopback
    - Request fails
    """
    if not API_KEY:
        return {'error': 'no_key', 'message': 'Set ABUSEIPDB_KEY env var for threat intel'}

    if _is_private(ip):
        return {
            'ip':           ip,
            'is_private':   True,
            'abuse_score':  0,
            'total_reports': 0,
            'country':      'Private',
            'isp':          'Internal Network',
            'source':       'local',
        }

    # Check cache
    if ip in _cache:
        result, expiry = _cache[ip]
        if datetime.now() < expiry:
            return result

    try:
        resp = requests.get(
            BASE_URL,
            headers={'Key': API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''},
            timeout=5,
        )

        if resp.status_code == 200:
            d = resp.json().get('data', {})
            result = {
                'ip':                ip,
                'is_private':        not d.get('isPublic', True),
                'abuse_score':       int(d.get('abuseConfidenceScore', 0)),
                'total_reports':     int(d.get('totalReports', 0)),
                'country':           d.get('countryCode', 'Unknown'),
                'isp':               d.get('isp', 'Unknown'),
                'domain':            d.get('domain', ''),
                'last_reported':     d.get('lastReportedAt'),
                'is_whitelisted':    d.get('isWhitelisted', False),
                'usage_type':        d.get('usageType', 'Unknown'),
                'source':            'AbuseIPDB',
                'risk_level':        _risk_level(d.get('abuseConfidenceScore', 0)),
            }
            _cache[ip] = (result, datetime.now() + timedelta(seconds=CACHE_TTL))
            return result

        if resp.status_code == 422:
            return {'error': 'invalid_ip', 'ip': ip}

        if resp.status_code == 429:
            return {'error': 'rate_limited', 'message': 'AbuseIPDB daily limit reached'}

    except requests.exceptions.Timeout:
        return {'error': 'timeout', 'message': 'AbuseIPDB request timed out'}
    except Exception as e:
        return {'error': 'exception', 'message': str(e)}

    return None


def _risk_level(score: int) -> str:
    if score >= 80:  return 'CRITICAL'
    if score >= 50:  return 'HIGH'
    if score >= 25:  return 'MEDIUM'
    if score >= 5:   return 'LOW'
    return 'CLEAN'


def get_cache_stats() -> dict:
    now = datetime.now()
    active = sum(1 for _, (_, exp) in _cache.items() if now < exp)
    return {'cached_ips': active, 'api_key_configured': bool(API_KEY)}
