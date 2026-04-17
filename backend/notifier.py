"""
INIDARS Email Notifier
Sends email alerts for CRITICAL threats via SMTP.

Configure with environment variables:
    SMTP_HOST     — e.g. smtp.gmail.com         (default: smtp.gmail.com)
    SMTP_PORT     — e.g. 587                    (default: 587)
    SMTP_USER     — your email address
    SMTP_PASS     — your email password / app password
    NOTIFY_EMAIL  — recipient email (can be same as SMTP_USER)

Gmail tip: use an App Password, not your main password.
  https://myaccount.google.com/apppasswords
"""

import os
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

SMTP_HOST    = os.environ.get('SMTP_HOST',    'smtp.gmail.com')
SMTP_PORT    = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER    = os.environ.get('SMTP_USER',    '')
SMTP_PASS    = os.environ.get('SMTP_PASS',    '')
NOTIFY_EMAIL = os.environ.get('NOTIFY_EMAIL', SMTP_USER)

_configured = bool(SMTP_USER and SMTP_PASS and NOTIFY_EMAIL)


def send_critical_alert(alert: dict):
    """
    Send a CRITICAL alert email asynchronously (non-blocking).
    Does nothing if SMTP is not configured.
    """
    if not _configured:
        return
    # Run in background so it never blocks event ingestion
    t = threading.Thread(target=_send, args=(alert,), daemon=True)
    t.start()


def _send(alert: dict):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[INIDARS] CRITICAL Alert — {alert.get('threat_type', 'Unknown Threat')}"
        msg['From']    = SMTP_USER
        msg['To']      = NOTIFY_EMAIL

        ts = alert.get('timestamp', '')[:19].replace('T', ' ')
        ip = alert.get('source_ip', 'N/A')

        # Plain-text fallback
        plain = (
            f"INIDARS CRITICAL SECURITY ALERT\n"
            f"{'=' * 40}\n"
            f"Threat Type : {alert.get('threat_type')}\n"
            f"Category    : {alert.get('attack_category')}\n"
            f"Source IP   : {ip}\n"
            f"ML Score    : {int((alert.get('ml_score') or 0) * 100)}%\n"
            f"Confidence  : {alert.get('confidence')}%\n"
            f"Time        : {ts}\n\n"
            f"Description : {alert.get('description')}\n"
            f"Action      : {alert.get('recommendation')}\n"
        )

        # HTML version
        sev_color = '#dc2626'
        html = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0a0e1f;color:#e2e8f0;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#1e293b;border-radius:12px;
                      border:1px solid #dc2626;overflow:hidden;">
            <div style="background:#dc2626;padding:20px 24px;">
              <h1 style="margin:0;color:#fff;font-size:20px;">
                &#x26A0; INIDARS CRITICAL ALERT
              </h1>
              <p style="margin:4px 0 0;color:#fecaca;font-size:13px;">{ts}</p>
            </div>
            <div style="padding:24px;">
              <table style="width:100%;border-collapse:collapse;">
                {''.join(f"""
                <tr>
                  <td style="padding:8px 0;color:#94a3b8;font-size:13px;width:140px;">{k}</td>
                  <td style="padding:8px 0;color:#f1f5f9;font-size:13px;font-weight:600;">{v}</td>
                </tr>""" for k, v in [
                    ('Threat Type',     alert.get('threat_type', '—')),
                    ('Attack Category', alert.get('attack_category', '—')),
                    ('Source IP',       ip),
                    ('ML Score',        f"{int((alert.get('ml_score') or 0) * 100)}%"),
                    ('Confidence',      f"{alert.get('confidence', 0)}%"),
                    ('Rule Matched',    'Yes' if alert.get('rule_matched') else 'No'),
                    ('Dest Port',       str(alert.get('dest_port', '—'))),
                    ('Protocol',        alert.get('protocol', '—')),
                ])}
              </table>
              <div style="margin-top:16px;padding:12px;background:#0f172a;border-radius:8px;
                          border-left:3px solid #dc2626;">
                <p style="margin:0 0 4px;color:#94a3b8;font-size:12px;">DESCRIPTION</p>
                <p style="margin:0;color:#e2e8f0;font-size:13px;">{alert.get('description', '')}</p>
              </div>
              <div style="margin-top:12px;padding:12px;background:#0f172a;border-radius:8px;
                          border-left:3px solid #f59e0b;">
                <p style="margin:0 0 4px;color:#94a3b8;font-size:12px;">RECOMMENDED ACTION</p>
                <p style="margin:0;color:#fbbf24;font-size:13px;font-weight:600;">
                  {alert.get('recommendation', '')}
                </p>
              </div>
            </div>
            <div style="padding:12px 24px;border-top:1px solid #334155;text-align:center;">
              <p style="margin:0;color:#475569;font-size:11px;">
                INIDARS — Intelligent Network Intrusion Detection &amp; Automated Response System
              </p>
            </div>
          </div>
        </body></html>
        """

        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html,  'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, NOTIFY_EMAIL, msg.as_string())

        print(f"[Notifier] CRITICAL alert email sent to {NOTIFY_EMAIL} for IP {ip}")

    except Exception as e:
        print(f"[Notifier] Failed to send email: {e}")


def get_status() -> dict:
    return {
        'configured':    _configured,
        'smtp_host':     SMTP_HOST if _configured else None,
        'smtp_port':     SMTP_PORT if _configured else None,
        'notify_email':  NOTIFY_EMAIL if _configured else None,
    }
