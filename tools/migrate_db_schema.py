# tools/migrate_db_schema.py
import sqlite3
import os
from pyrewall.db.paths import FIREWALL_DB, USERS_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB

def ensure_table(conn, sql_create):
    cur = conn.cursor()
    cur.execute(sql_create)
    conn.commit()

def add_column_if_missing(conn, table, column, col_def):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(%s)" % table)
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
        conn.commit()
        print(f"Added column {column} to {table}")

def migrate_firewall_db():
    os.makedirs(os.path.dirname(FIREWALL_DB), exist_ok=True)
    conn = sqlite3.connect(FIREWALL_DB)
    # blocked_ips table with expanded schema
    ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        domain TEXT,
        expires_at DATETIME,
        reason TEXT
    )
    """)
    ensure_table(conn, "CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
    conn.close()
    print("Firewall DB migrated:", FIREWALL_DB)

def migrate_users_db():
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
    """)
    # Make sure role exists (ALTER TABLE safe-guard)
    add_column_if_missing(conn, "users", "role", "TEXT DEFAULT 'user'")
    conn.close()
    print("Users DB migrated:", USERS_DB)

def migrate_history_and_logs():
    os.makedirs(os.path.dirname(GENERAL_HISTORY_DB), exist_ok=True)
    conn = sqlite3.connect(GENERAL_HISTORY_DB)
    ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        description TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.close()
    os.makedirs(os.path.dirname(FIREWALL_LOGS_DB), exist_ok=True)
    conn = sqlite3.connect(FIREWALL_LOGS_DB)
    ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS firewall_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        domain TEXT,
        action TEXT
    )
    """)
    conn.close()
    print("History and logs migrated")

if __name__ == "__main__":
    migrate_firewall_db()
    migrate_users_db()
    migrate_history_and_logs()
    print("Migration complete. Verify apps can open DBs now.")
