"""Trusted contact: one person who can be alerted with a minimal message after the user confirms.

Shared with the contact: severity, UTC time, evidence hash, and the sender name the user chose.
Never shared: evidence text, screenshots, location, identifiers, category. Never sent automatically.
Delivery honesty: the best this module can know is that the mail server ACCEPTED the message.
It cannot know it was delivered or read.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import time
from datetime import datetime, timezone
from email.message import EmailMessage

import db
import security as sec

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
CODE_TTL = 15 * 60
MAX_CODE_ATTEMPTS = 5
CONFIRM_TTL = 120
_pending = {}  # confirm_token -> dict(user_id, evidence_id, message, expires)


class ContactError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def smtp_configured():
    return bool(os.environ.get("SHESHIELD_SMTP_HOST"))


def _send_mail(to, subject, body):
    host = os.environ.get("SHESHIELD_SMTP_HOST")
    if not host:
        raise ContactError(503, "Email sending is not set up on this server. Set SHESHIELD_SMTP_HOST (see README).")
    port = int(os.environ.get("SHESHIELD_SMTP_PORT", "587"))
    user, pw = os.environ.get("SHESHIELD_SMTP_USER"), os.environ.get("SHESHIELD_SMTP_PASSWORD")
    sender = os.environ.get("SHESHIELD_SMTP_FROM") or user or "sheshield@localhost"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg.set_content(body)
    try:
        if os.environ.get("SHESHIELD_SMTP_SSL") == "1":
            s = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(host, port, timeout=15)
            if os.environ.get("SHESHIELD_SMTP_STARTTLS", "1") == "1":
                s.starttls(context=ssl.create_default_context())
        try:
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)
        finally:
            try:
                s.quit()
            except Exception:
                pass
    except ContactError:
        raise
    except Exception as e:
        raise ContactError(502, f"The mail server did not accept the message ({type(e).__name__}).")


def _code_hash(user_id, code):
    return hashlib.sha256(f"contact|{user_id}|{code}".encode()).hexdigest()


def _row(c, user_id):
    return c.execute("SELECT * FROM contacts WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()


def _mask(email):
    n, d = email.split("@", 1)
    return (n[0] + "***" if n else "***") + "@" + d


def _open(ctx, row):
    return json.loads(sec.unseal(ctx.dek, bytes(row["blob"]), f"contact|{ctx.user_id}".encode()).decode())


def get(ctx):
    c = db.connect()
    try:
        row = _row(c, ctx.user_id)
        if not row:
            return {"exists": False, "smtp_configured": smtp_configured()}
        d = _open(ctx, row)
        return {"exists": True, "name": d["name"], "email_masked": _mask(d["email"]), "sender_name": d.get("sender_name", ""),
                "verified": bool(row["verified"]), "smtp_configured": smtp_configured()}
    finally:
        c.close()


def add(ctx, name, email, sender_name):
    name, email, sender_name = (name or "").strip(), (email or "").strip().lower(), (sender_name or "").strip()
    if not (1 <= len(name) <= 80):
        raise ContactError(400, "Enter the contact's name (up to 80 characters).")
    if not EMAIL_RE.match(email):
        raise ContactError(400, "Enter a valid email address.")
    if len(sender_name) > 60:
        raise ContactError(400, "Your sender name is too long (60 characters max).")
    code = f"{secrets.randbelow(10**6):06d}"
    body = (f"Someone has named you as a trusted contact on SheShield, a safety tool.\n\n"
            f"Your verification code is: {code}\n\n"
            "They will be asked to type this code. If you do not know why you received this, ignore this email; "
            "nothing is shared unless the code is entered.\nThe code expires in 15 minutes.")
    _send_mail(email, "SheShield: verification code for a trusted contact", body)  # fail before storing
    blob = sec.seal(ctx.dek, json.dumps({"name": name, "email": email, "sender_name": sender_name}).encode(),
                    f"contact|{ctx.user_id}".encode())
    c = db.connect()
    try:
        c.execute("DELETE FROM contacts WHERE user_id=?", (ctx.user_id,))
        c.execute("INSERT INTO contacts (user_id, blob, verified, code_hash, code_expires, code_attempts, created_at) VALUES (?,?,?,?,?,?,?)",
                  (ctx.user_id, blob, 0, _code_hash(ctx.user_id, code), time.time() + CODE_TTL, 0,
                   datetime.now(timezone.utc).isoformat()))
        c.commit()
    finally:
        c.close()
    return get(ctx)


def verify(ctx, code):
    code = re.sub(r"\D", "", code or "")
    c = db.connect()
    try:
        row = _row(c, ctx.user_id)
        if not row:
            raise ContactError(404, "No trusted contact has been added.")
        if row["verified"]:
            return get(ctx)
        if row["code_attempts"] >= MAX_CODE_ATTEMPTS or time.time() > (row["code_expires"] or 0):
            raise ContactError(410, "That code has expired or was tried too many times. Add the contact again to get a new one.")
        if not hmac.compare_digest(_code_hash(ctx.user_id, code), row["code_hash"] or ""):
            c.execute("UPDATE contacts SET code_attempts=code_attempts+1 WHERE id=?", (row["id"],))
            c.commit()
            raise ContactError(400, "That code is not correct.")
        c.execute("UPDATE contacts SET verified=1, code_hash=NULL WHERE id=?", (row["id"],))
        c.commit()
    finally:
        c.close()
    return get(ctx)


def remove(ctx):
    c = db.connect()
    try:
        n = c.execute("DELETE FROM contacts WHERE user_id=?", (ctx.user_id,)).rowcount
        c.commit()
        return {"removed": bool(n)}
    finally:
        c.close()


def _compose(sender_name, severity, ts, ev_hash):
    who = sender_name or "A SheShield user"
    return (f"{who} asked SheShield to let you know they may need support.\n\n"
            f"Severity of the incident they recorded: {severity.upper()}\n"
            f"Recorded at (UTC): {ts}\n"
            f"Tamper-evident evidence fingerprint: {ev_hash}\n\n"
            "This message does not include any messages, photos, names or location. "
            "Please contact them directly and calmly, and ask how you can help. "
            "Do not forward this message. If they are in danger, call 112.")


def prepare_alert(ctx, record):
    """Step 1 of 2. Returns exactly what would be sent, plus a short-lived confirmation token. Sends nothing."""
    c = db.connect()
    try:
        row = _row(c, ctx.user_id)
        if not row or not row["verified"]:
            raise ContactError(409, "Add and verify a trusted contact first.")
        d = _open(ctx, row)
    finally:
        c.close()
    msg = _compose(d.get("sender_name", ""), record["severity"], record["created_at"], record["hash"])
    token = secrets.token_urlsafe(24)
    now = time.time()
    for k in [k for k, v in _pending.items() if v["expires"] < now]:
        _pending.pop(k, None)
    _pending[token] = dict(user_id=ctx.user_id, evidence_id=record["id"], severity=record["severity"], message=msg,
                           expires=now + CONFIRM_TTL)
    return {"confirm_token": token, "expires_in": CONFIRM_TTL, "to": _mask(d["email"]), "to_name": d["name"],
            "message": msg, "shared": ["Severity level", "Time of the record (UTC)", "Evidence fingerprint (hash)", "The sender name you chose"],
            "not_shared": ["Message text", "Screenshots", "Phone numbers, accounts or links", "Your location", "Your PIN or vault name"]}


def cancel_alert(ctx, token):
    p = _pending.get(token)
    if p and p["user_id"] == ctx.user_id:
        _pending.pop(token, None)
    return {"cancelled": True}


def _log(user_id, evidence_id, severity, status, detail):
    c = db.connect()
    try:
        c.execute("INSERT INTO alert_log (user_id, created_at, evidence_id, severity, channel, status, detail) VALUES (?,?,?,?,?,?,?)",
                  (user_id, datetime.now(timezone.utc).isoformat(), evidence_id, severity, "email", status, detail))
        c.commit()
    finally:
        c.close()


def send_alert(ctx, token):
    """Step 2 of 2. Only works with a live token the user got from prepare_alert."""
    p = _pending.pop(token, None)
    if not p or p["user_id"] != ctx.user_id or p["expires"] < time.time():
        raise ContactError(410, "This confirmation has expired or was cancelled. Start again if you still want to alert your contact.")
    c = db.connect()
    try:
        row = _row(c, ctx.user_id)
        if not row or not row["verified"]:
            raise ContactError(409, "Trusted contact is not verified.")
        d = _open(ctx, row)
    finally:
        c.close()
    try:
        _send_mail(d["email"], "SheShield: someone may need your support", p["message"])
    except ContactError as e:
        _log(ctx.user_id, p["evidence_id"], p["severity"], "failed", e.message)
        raise
    _log(ctx.user_id, p["evidence_id"], p["severity"], "accepted_by_mail_server", "Mail server accepted the message. Delivery or reading cannot be confirmed.")
    return {"status": "accepted_by_mail_server",
            "note": "The mail server accepted the message. SheShield cannot tell whether it was delivered or read."}


def history(ctx):
    c = db.connect()
    try:
        rows = c.execute("SELECT created_at, evidence_id, severity, channel, status, detail FROM alert_log WHERE user_id=? ORDER BY id DESC LIMIT 20",
                         (ctx.user_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        c.close()
