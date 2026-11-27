import sqlite3
import hashlib
from datetime import datetime, timezone

DB = "vault.db"


def _conn():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT, content TEXT, severity TEXT, score INTEGER,
        hash TEXT, prev_hash TEXT)""")
    return c


def _hash(ts, content, prev):
    return hashlib.sha256(f"{ts}|{content}|{prev}".encode("utf-8")).hexdigest()


def add(content, severity, score):
    c = _conn()
    row = c.execute("SELECT hash FROM evidence ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else "GENESIS"
    ts = datetime.now(timezone.utc).isoformat()
    h = _hash(ts, content, prev)
    cur = c.execute(
        "INSERT INTO evidence (created_at, content, severity, score, hash, prev_hash) "
        "VALUES (?,?,?,?,?,?)", (ts, content, severity, score, h, prev))
    c.commit()
    return {"id": cur.lastrowid, "created_at": ts, "severity": severity,
            "score": score, "hash": h}


def list_all():
    c = _conn()
    rows = c.execute(
        "SELECT id, created_at, content, severity, score, hash FROM evidence ORDER BY id").fetchall()
    return [dict(zip(["id", "created_at", "content", "severity", "score", "hash"], r))
            for r in rows]


def verify_all():
    c = _conn()
    rows = c.execute(
        "SELECT id, created_at, content, hash, prev_hash FROM evidence ORDER BY id").fetchall()
    prev = "GENESIS"
    for id_, ts, content, h, p in rows:
        if p != prev or _hash(ts, content, p) != h:
            return {"ok": False, "tampered_at_id": id_}
        prev = h
    return {"ok": True, "items_checked": len(rows)}