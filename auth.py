"""Accounts: registration, PIN login with lockout, PIN change, recovery and wipe."""
import re
import time
from datetime import datetime, timezone

import db
import security as sec
from cryptography.exceptions import InvalidTag

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")


class AuthError(Exception):
    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


def _label(username):
    return username.encode("utf-8")


def clean_username(u):
    u = (u or "").strip().lower()
    if not USERNAME_RE.match(u):
        raise AuthError(400, "Vault name must be 3 to 32 characters: letters, numbers, dot, dash or underscore.")
    return u


def legacy_available():
    c = db.connect()
    try:
        return c.execute("SELECT 1 FROM evidence WHERE user_id IS NULL LIMIT 1").fetchone() is not None
    finally:
        c.close()


def user_count():
    c = db.connect()
    try:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        c.close()


def register(username, pin, claim_legacy=False):
    username = clean_username(username)
    try:
        sec.validate_pin(pin)
    except ValueError as e:
        raise AuthError(400, str(e))
    dek = sec.new_dek()
    kek_salt, wrapped = sec.wrap_dek(pin, dek, _label(username))
    code = sec.new_recovery_code()
    rec_salt, rec_wrapped = sec.wrap_dek(sec.normalise_recovery_code(code), dek, _label(username))
    c = db.connect()
    try:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise AuthError(409, "That vault name is already taken. Choose another.")
        cur = c.execute(
            "INSERT INTO users (username, pin_hash, kek_salt, wrapped_dek, rec_salt, rec_wrapped_dek, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (username, sec.hash_pin(pin), kek_salt, wrapped, rec_salt, rec_wrapped,
             datetime.now(timezone.utc).isoformat()))
        uid = cur.lastrowid
        c.commit()
    finally:
        c.close()
    if claim_legacy:
        import vault
        vault.claim_legacy(uid, dek)
    return uid, code, dek


def login(username, pin):
    username = (username or "").strip().lower()
    c = db.connect()
    try:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            # equalise timing so vault names cannot be probed
            sec.hash_pin("dummy-pin-for-timing")
            raise AuthError(401, "Incorrect vault name or PIN.")
        now = time.time()
        if row["locked_until"] > now:
            wait = int(row["locked_until"] - now) + 1
            raise AuthError(429, f"Too many attempts. Try again in {wait} seconds.", wait)
        if not sec.verify_pin(row["pin_hash"], pin or ""):
            failed = row["failed_attempts"] + 1
            wait = sec.lockout_seconds(failed)
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                      (failed, now + wait if wait else 0, row["id"]))
            c.commit()
            if wait:
                raise AuthError(429, f"Too many attempts. Locked for {wait} seconds.", wait)
            left = 5 - failed
            raise AuthError(401, f"Incorrect vault name or PIN. {left} attempt{'s' if left != 1 else ''} left before a temporary lock.")
        try:
            dek = sec.unwrap_dek(pin, bytes(row["kek_salt"]), bytes(row["wrapped_dek"]), _label(username))
        except InvalidTag:
            raise AuthError(500, "This vault's key could not be unlocked. The database may be damaged.")
        c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (row["id"],))
        c.commit()
        return row["id"], row["username"], dek
    finally:
        c.close()


def change_pin(user_id, username, old_pin, new_pin):
    try:
        sec.validate_pin(new_pin)
    except ValueError as e:
        raise AuthError(400, str(e))
    uid, uname, dek = login(username, old_pin)
    salt, wrapped = sec.wrap_dek(new_pin, dek, _label(uname))
    c = db.connect()
    try:
        c.execute("UPDATE users SET pin_hash=?, kek_salt=?, wrapped_dek=? WHERE id=?",
                  (sec.hash_pin(new_pin), salt, wrapped, uid))
        c.commit()
    finally:
        c.close()


def recover(username, recovery_code, new_pin):
    username = clean_username(username)
    try:
        sec.validate_pin(new_pin)
    except ValueError as e:
        raise AuthError(400, str(e))
    c = db.connect()
    try:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        now = time.time()
        if not row or not row["rec_salt"]:
            raise AuthError(401, "Recovery code did not work.")
        if row["locked_until"] > now:
            wait = int(row["locked_until"] - now) + 1
            raise AuthError(429, f"Too many attempts. Try again in {wait} seconds.", wait)
        try:
            dek = sec.unwrap_dek(sec.normalise_recovery_code(recovery_code), bytes(row["rec_salt"]),
                                 bytes(row["rec_wrapped_dek"]), _label(username))
        except InvalidTag:
            failed = row["failed_attempts"] + 1
            wait = sec.lockout_seconds(failed)
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                      (failed, now + wait if wait else 0, row["id"]))
            c.commit()
            raise AuthError(401, "Recovery code did not work.")
        salt, wrapped = sec.wrap_dek(new_pin, dek, _label(username))
        c.execute("UPDATE users SET pin_hash=?, kek_salt=?, wrapped_dek=?, failed_attempts=0, locked_until=0 WHERE id=?",
                  (sec.hash_pin(new_pin), salt, wrapped, row["id"]))
        c.commit()
        return row["id"], row["username"], dek
    finally:
        c.close()


def wipe_user(user_id):
    """Delete everything belonging to one account, including its wrapped keys.

    Returns counts of what was removed. Blockchain transactions and any copies the user
    made elsewhere (PDF reports, screenshots, forwarded alerts) are NOT affected.
    """
    c = db.connect()
    try:
        counts = {}
        for table, key in [("evidence", "evidence"), ("analysis_log", "analysis_log"),
                           ("contacts", "contacts"), ("alert_log", "alert_log"), ("anchors", "anchors")]:
            counts[key] = c.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,)).rowcount
        counts["account"] = c.execute("DELETE FROM users WHERE id=?", (user_id,)).rowcount
        c.commit()
        c.execute("VACUUM")
    finally:
        c.close()
    sec.end_user_sessions(user_id)
    return counts
