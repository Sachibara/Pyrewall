# pyrewall/db/app_signatures.py
"""
App signature storage helpers.

This module now uses the canonical DB path exported by pyrewall.db.paths
to reliably open the project's firewall database regardless of CWD.
"""

import os
import sqlite3
from typing import List, Tuple

# Use canonical path exported by the package
from pyrewall.db.paths import FIREWALL_DB as DB

def _ensure_db_parent(db_path: str):
    """Ensure the parent directory exists so sqlite can create/open the file."""
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

def init_app_signatures(db_path: str = None):
    db = db_path or DB
    _ensure_db_parent(db)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT UNIQUE,
            pattern TEXT,
            ip_range TEXT,
            protocol TEXT,
            domain_pattern TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_signature(app_name: str, pattern: str = None, ip_range: str = None, protocol: str = None, domain_pattern: str = None, db_path: str = None):
    db = db_path or DB
    _ensure_db_parent(db)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO app_signatures (app_name, pattern, ip_range, protocol, domain_pattern) VALUES (?, ?, ?, ?, ?)",
                (app_name, pattern, ip_range, protocol, domain_pattern))
    conn.commit()
    conn.close()

def remove_signature(app_name: str = None, signature_id: int = None, db_path: str = None):
    db = db_path or DB
    _ensure_db_parent(db)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    if signature_id is not None:
        cur.execute("DELETE FROM app_signatures WHERE id = ?", (signature_id,))
    elif app_name:
        cur.execute("DELETE FROM app_signatures WHERE app_name = ?", (app_name,))
    conn.commit()
    conn.close()

def get_all_signatures(db_path: str = None) -> List[Tuple]:
    """Return list of tuples: (id, app_name, pattern, ip_range, protocol, domain_pattern)"""
    db = db_path or DB
    init_app_signatures(db)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT id, app_name, pattern, ip_range, protocol, domain_pattern FROM app_signatures ORDER BY app_name ASC")
    rows = cur.fetchall()
    conn.close()
    return rows
