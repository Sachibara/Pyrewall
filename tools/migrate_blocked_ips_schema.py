# pyrewall/tools/migrate_blocked_ips_schema.py
import os
import sqlite3
from pyrewall.db.paths import FIREWALL_DB as DB

def ensure_schema(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY)")
    cur.execute("PRAGMA table_info(blocked_ips)")
    existing = {row[1] for row in cur.fetchall()}
    extras = {"domain": "TEXT", "expires_at": "DATETIME", "reason": "TEXT"}
    for col, coltype in extras.items():
        if col not in existing:
            try:
                cur.execute(f"ALTER TABLE blocked_ips ADD COLUMN {col} {coltype}")
            except Exception as e:
                print("failed to add", col, e)
    conn.commit()
    conn.close()
    print("migration done for", db_path)

if __name__ == "__main__":
    ensure_schema(DB)
