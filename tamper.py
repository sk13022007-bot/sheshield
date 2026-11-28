"""Demo helper: simulate someone editing a saved record directly in the database file.

Records are encrypted, so this flips bytes in the stored ciphertext. The next integrity check fails
(AES-GCM authentication fails), which the app reports as tampering.

    python tamper.py <id>        damage record <id>
    python tamper.py restore     put the original back
Uses SHESHIELD_DB (default vault.db).
"""
import json
import os
import sqlite3
import sys

DB = os.environ.get("SHESHIELD_DB", "vault.db")
BACKUP = "tamper_backup.json"


def tamper(row_id):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT content, enc FROM evidence WHERE id = ?", (row_id,)).fetchone()
    if row is None:
        print("No evidence with id", row_id)
        return
    original, enc = row
    with open(BACKUP, "w", encoding="utf-8") as f:
        json.dump({"id": row_id, "content": original}, f)
    # change one character: for ciphertext this breaks authentication; for legacy plaintext it changes the text
    new = ("A" if original[:1] != "A" else "B") + original[1:] if enc else original + " (edited)"
    con.execute("UPDATE evidence SET content = ? WHERE id = ?", (new, row_id))
    con.commit()
    con.close()
    print("Tampered with evidence", row_id, "- now run Verify in the vault.")


def restore():
    if not os.path.exists(BACKUP):
        print("Nothing to restore.")
        return
    data = json.load(open(BACKUP, encoding="utf-8"))
    con = sqlite3.connect(DB)
    con.execute("UPDATE evidence SET content = ? WHERE id = ?", (data["content"], data["id"]))
    con.commit()
    con.close()
    os.remove(BACKUP)
    print("Restored evidence", data["id"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        restore()
    else:
        tamper(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
