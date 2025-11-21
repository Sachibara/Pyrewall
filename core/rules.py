"""
CRUD operations for firewall rules.
"""

import sqlite3
from pyrewall.db.paths import FIREWALL_DB as DB_PATH


def create_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port TEXT,
            protocol TEXT,
            action TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_rules():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT ip, port, protocol, action FROM firewall_rules")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_rule(ip, port, protocol, action):
    create_table()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO firewall_rules(ip, port, protocol, action) VALUES (?, ?, ?, ?)",
                (ip, port, protocol, action))
    conn.commit()
    conn.close()
