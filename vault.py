"""Per-user, encrypted, hash-chained evidence vault.

Integrity (unchanged idea): every record stores hash = SHA-256(timestamp | content | prev_hash)
and records are chained per user, so any edit breaks the chain.

Confidentiality (new): content and metadata are encrypted with the user's AES-256-GCM key.
The ciphertext is authenticated, bound to the user and record timestamp, so swapping or
editing it fails to decrypt and is reported as tampering.

What is NOT encrypted: record id, timestamp, severity, score and the hashes. They are needed
to list, chain and anchor records without unlocking each one. See README.
"""
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

import db
import security as sec


def _hash_v1(ts, content, prev):
    return hashlib.sha256(f"{ts}|{content}|{prev}".encode("utf-8")).hexdigest()


def _canon(meta):
    return json.dumps(meta or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_v2(ts, content, meta, prev):
    return hashlib.sha256(f"{ts}|{content}|{_canon(meta)}|{prev}".encode("utf-8")).hexdigest()


def _aad(user_id, ts):
    return f"evidence|{user_id}|{ts}".encode("utf-8")


def _enc(ctx, ts, text):
    return sec.b64e(sec.seal(ctx.dek, text.encode("utf-8"), _aad(ctx.user_id, ts)))


def _dec(ctx, ts, blob):
    return sec.unseal(ctx.dek, sec.b64d(blob), _aad(ctx.user_id, ts)).decode("utf-8")


def add(ctx, content, severity, score, meta=None):
    """Save one record. ctx is a security.Session (user_id + data key)."""
    meta = meta or {}
    c = db.connect()
    try:
        row = c.execute("SELECT hash FROM evidence WHERE user_id=? ORDER BY id DESC LIMIT 1",
                        (ctx.user_id,)).fetchone()
        prev = row["hash"] if row else "GENESIS"
        ts = datetime.now(timezone.utc).isoformat()
        h = _hash_v2(ts, content, meta, prev)
        cur = c.execute(
            "INSERT INTO evidence (created_at, content, severity, score, hash, prev_hash, user_id, enc, meta, hv) "
            "VALUES (?,?,?,?,?,?,?,1,?,2)",
            (ts, _enc(ctx, ts, content), severity, score, h, prev, ctx.user_id, _enc(ctx, ts, _canon(meta))))
        c.commit()
        return {"id": cur.lastrowid, "created_at": ts, "severity": severity, "score": score, "hash": h}
    finally:
        c.close()


def _rows(c, ctx):
    return c.execute("SELECT * FROM evidence WHERE user_id=? ORDER BY id", (ctx.user_id,)).fetchall()


def _open(ctx, r):
    """Return (content, meta, ok). ok is False when authentication fails."""
    if not r["enc"]:
        return r["content"], {}, True
    try:
        content = _dec(ctx, r["created_at"], r["content"])
        meta = json.loads(_dec(ctx, r["created_at"], r["meta"])) if r["meta"] else {}
        return content, meta, True
    except (InvalidTag, ValueError, TypeError):
        return None, {}, False


def _expected(r, content, meta):
    if r["hv"] == 2:
        return _hash_v2(r["created_at"], content, meta, r["prev_hash"])
    return _hash_v1(r["created_at"], content, r["prev_hash"])


def list_all(ctx):
    c = db.connect()
    try:
        out = []
        for r in _rows(c, ctx):
            content, meta, ok = _open(ctx, r)
            out.append({
                "id": r["id"], "created_at": r["created_at"],
                "content": content if ok else "[This record could not be decrypted. It may have been altered.]",
                "severity": r["severity"], "score": r["score"], "hash": r["hash"],
                "prev_hash": r["prev_hash"], "meta": meta, "readable": ok,
            })
        return out
    finally:
        c.close()


def verify_all(ctx):
    c = db.connect()
    try:
        prev = "GENESIS"
        rows = _rows(c, ctx)
        for r in rows:
            content, meta, ok = _open(ctx, r)
            if not ok or r["prev_hash"] != prev or _expected(r, content, meta) != r["hash"]:
                return {"ok": False, "tampered_at_id": r["id"]}
            prev = r["hash"]
        return {"ok": True, "items_checked": len(rows)}
    finally:
        c.close()


def latest_hash(ctx):
    c = db.connect()
    try:
        r = c.execute("SELECT hash FROM evidence WHERE user_id=? ORDER BY id DESC LIMIT 1", (ctx.user_id,)).fetchone()
        return r["hash"] if r else None
    finally:
        c.close()


def claim_legacy(user_id, dek):
    """Adopt rows saved before accounts existed. Their hashes stay valid; content becomes encrypted."""
    ctx = sec.Session(user_id, "", dek, 0)
    c = db.connect()
    try:
        rows = c.execute("SELECT * FROM evidence WHERE user_id IS NULL ORDER BY id").fetchall()
        for r in rows:
            c.execute("UPDATE evidence SET user_id=?, enc=1, content=?, meta=? WHERE id=?",
                      (user_id, _enc(ctx, r["created_at"], r["content"] or ""), _enc(ctx, r["created_at"], "{}"), r["id"]))
        # anchors saved in the old anchors.json file are claimed too (hv stays 1 for these rows)
        c.commit()
        return len(rows)
    finally:
        c.close()
