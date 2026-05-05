"""
Email (Resend) + Push Notifications (Expo) helpers.
All functions are non-blocking and never raise — failures are logged silently
so the main API request can complete successfully.
"""
import os
import asyncio
import logging
from typing import Optional, List

import httpx
import resend

logger = logging.getLogger("nuntamea.notifications")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev").strip()
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "https://nuntamea-backend.onrender.com").strip().rstrip("/")
EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY
    logger.info("Resend configured (from=%s)", RESEND_FROM_EMAIL)
else:
    logger.warning("RESEND_API_KEY not set — emails will be skipped")


# ---------- Email (Resend) ----------
async def send_email(
    to: str,
    subject: str,
    html: str,
    text_fallback: Optional[str] = None,
) -> bool:
    """Send an email via Resend. Returns True on success, False on failure (never raises)."""
    if not RESEND_API_KEY:
        logger.warning("Skipping email to %s — RESEND_API_KEY not set", to)
        return False
    if not to:
        return False
    params = {
        "from": RESEND_FROM_EMAIL,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text_fallback:
        params["text"] = text_fallback
    try:
        result = await asyncio.to_thread(resend.Emails.send, params)
        logger.info("Email sent to %s id=%s", to, result.get("id"))
        return True
    except Exception as e:
        logger.error("Email send failed to %s: %s", to, e)
        return False


def build_password_reset_email(user_name: str, reset_link: str) -> tuple[str, str]:
    """Returns (subject, html) for password reset email."""
    subject = "Resetare parolă — Nunta Mea"
    html = f"""<!DOCTYPE html>
<html lang="ro"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#FFF8F5;font-family:Georgia,serif;color:#2A1F2D">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#FFF8F5;padding:32px 16px">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:520px;background:#fff;border-radius:18px;padding:36px 28px;box-shadow:0 4px 16px rgba(232,120,154,0.12)" cellspacing="0" cellpadding="0">
<tr><td align="center" style="padding-bottom:8px">
  <div style="font-size:42px">💍</div>
  <h1 style="font-family:Georgia,serif;font-size:26px;color:#E8789A;margin:8px 0 0">Nunta Mea</h1>
</td></tr>
<tr><td style="padding-top:24px;font-family:Inter,Arial,sans-serif;font-size:15px;color:#2A1F2D;line-height:1.6">
  <p style="margin:0 0 16px">Bună{(' ' + user_name) if user_name else ''},</p>
  <p style="margin:0 0 16px">Ai cerut resetarea parolei pentru contul tău Nunta Mea.</p>
  <p style="margin:0 0 24px">Apasă pe butonul de mai jos pentru a-ți seta o parolă nouă (link valabil 1 oră):</p>
</td></tr>
<tr><td align="center" style="padding:8px 0 24px">
  <a href="{reset_link}" style="display:inline-block;background:#E8789A;color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-family:Inter,Arial,sans-serif;font-size:15px;font-weight:600">Resetează parola</a>
</td></tr>
<tr><td style="font-family:Inter,Arial,sans-serif;font-size:12px;color:#8B7A86;line-height:1.5;border-top:1px solid #F1E4E0;padding-top:16px">
  <p style="margin:0 0 8px">Dacă nu tu ai cerut resetarea, ignoră acest email — contul tău e în siguranță.</p>
  <p style="margin:0;word-break:break-all">Sau copiază linkul: <span style="color:#E8789A">{reset_link}</span></p>
</td></tr>
</table>
<p style="font-family:Inter,Arial,sans-serif;font-size:11px;color:#B8A5AC;margin-top:16px">© Nunta Mea — planificarea nunții tale, cu suflet</p>
</td></tr></table>
</body></html>"""
    return subject, html


def build_rsvp_notification_email(couple_name: str, guest_name: str, status: str) -> tuple[str, str]:
    status_label = "a confirmat ✓" if status == "confirmat" else "a refuzat ✗"
    color = "#7BC9A4" if status == "confirmat" else "#E27676"
    subject = f"{guest_name} {status_label} — Nunta Mea"
    html = f"""<!DOCTYPE html>
<html lang="ro"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#FFF8F5;font-family:Georgia,serif;color:#2A1F2D">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#FFF8F5;padding:32px 16px">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:520px;background:#fff;border-radius:18px;padding:36px 28px" cellspacing="0" cellpadding="0">
<tr><td align="center"><div style="font-size:42px">💌</div></td></tr>
<tr><td style="padding-top:16px;font-family:Inter,Arial,sans-serif;font-size:15px;line-height:1.6">
  <p style="margin:0 0 8px">Bună{(' ' + couple_name) if couple_name else ''},</p>
  <p style="margin:0 0 16px">Un nou răspuns la invitație:</p>
  <div style="background:#FFF8F5;border-left:4px solid {color};padding:14px 16px;border-radius:6px;margin:16px 0">
    <p style="margin:0;font-size:18px;font-family:Georgia,serif"><strong>{guest_name}</strong></p>
    <p style="margin:6px 0 0;color:{color};font-weight:600">{status_label}</p>
  </div>
  <p style="margin:24px 0 0;color:#8B7A86;font-size:13px">Vezi toate răspunsurile direct în aplicație 📱</p>
</td></tr>
</table>
</td></tr></table>
</body></html>"""
    return subject, html


# ---------- Push Notifications (Expo) ----------
async def send_push(
    tokens: List[str],
    title: str,
    body: str,
    data: Optional[dict] = None,
) -> bool:
    """Send push notification(s) via Expo. Returns True on success, never raises."""
    if not tokens:
        return False
    valid_tokens = [t for t in tokens if t and t.startswith("ExponentPushToken[")]
    if not valid_tokens:
        return False
    payload = [{
        "to": t,
        "sound": "default",
        "title": title,
        "body": body,
        "data": data or {},
    } for t in valid_tokens]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(EXPO_PUSH_URL, json=payload)
            r.raise_for_status()
            logger.info("Push sent to %d tokens", len(valid_tokens))
            return True
    except Exception as e:
        logger.error("Push send failed: %s", e)
        return False
