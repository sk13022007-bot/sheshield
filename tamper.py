import json
import os
import sqlite3
import sys

DB = "vault.db"
BACKUP = "tamper_backup.json"


def tamper(row_id):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT content FROM evidence WHERE id = ?", (row_id,))
    row = cur.fetchone()
    if row is None:
        print("No evidence with id", row_id)
        con.close()
        return
    original = row[0]
    with open(BACKUP, "w", encoding="utf-8") as f:
        json.dump({"id": row_id, "content": original}, f)
    cur.execute("UPDATE evidence SET content = ? WHERE id = ?",
                (original + " (edited)", row_id))
    con.commit()
    con.close()
    print("Tampered with evidence", row_id, "- now click Verify vault.")


def restore():
    if not os.path.exists(BACKUP):
        print("Nothing to restore.")
        return
    with open(BACKUP, "r", encoding="utf-8") as f:
        data = json.load(f)
    con = sqlite3.connect(DB)
    con.execute("UPDATE evidence SET content = ? WHERE id = ?",
                (data["content"], data["id"]))
    con.commit()
    con.close()
    os.remove(BACKUP)
    print("Restored evidence", data["id"], "- vault should verify OK again.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        restore()
    else:
        row = int(sys.argv[1]) if len(sys.argv) > 1 else 1
        tamper(row)