"""SQLite access and schema for SheShield.

The database file is vault.db next to the app by default. Override with SHESHIELD_DB.
Older single-user databases are upgraded in place; their rows keep user_id NULL until
the first account chooses to claim them (see auth.claim_legacy).
"""
import os
import sqlite3

def db_path():
    return os.environ.get("SHESHIELD_DB", "vault.db")


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pin_hash TEXT NOT NULL,
        kek_salt BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        rec_salt BLOB,
        rec_wrapped_dek BLOB,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT, content TEXT, severity TEXT, score INTEGER,
        hash TEXT, prev_hash TEXT)""",
    """CREATE TABLE IF NOT EXISTS analysis_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        category TEXT, severity TEXT, score INTEGER, language TEXT, source TEXT)""",
    """CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        blob BLOB NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        code_hash TEXT, code_expires REAL, code_attempts INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS alert_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        evidence_id INTEGER, severity TEXT, channel TEXT, status TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS anchors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        tx_hash TEXT NOT NULL,
        vault_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'legacy',
        chain_id TEXT, contract TEXT)""",
]

# columns added to evidence after the first release
EVIDENCE_COLUMNS = {
    "user_id": "INTEGER",
    "enc": "INTEGER NOT NULL DEFAULT 0",   # 1 = content/meta are AES-256-GCM encrypted
    "meta": "TEXT",                         # base64(nonce||ciphertext) of JSON metadata
    "hv": "INTEGER NOT NULL DEFAULT 1",    # hash version (1 = legacy formula, 2 = includes meta)
}


def connect():
    c = sqlite3.connect(db_path())
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    for stmt in SCHEMA:
        c.execute(stmt)
    have = {r["name"] for r in c.execute("PRAGMA table_info(evidence)")}
    for col, decl in EVIDENCE_COLUMNS.items():
        if col not in have:
            c.execute(f"ALTER TABLE evidence ADD COLUMN {col} {decl}")
    have_a = {r["name"] for r in c.execute("PRAGMA table_info(anchors)")}
    if "state" not in have_a:
        c.execute("ALTER TABLE anchors ADD COLUMN state TEXT NOT NULL DEFAULT 'submitted'")
    c.execute("CREATE INDEX IF NOT EXISTS ev_user ON evidence(user_id, id)")
    c.commit()
    return c
