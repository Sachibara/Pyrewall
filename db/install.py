# pyrewall/db/install.py
"""
Installation / first-run helpers.

Function:
    ensure_fresh_installation() -> dict

Behavior:
- If run on a fresh machine (no marker present), it will:
  * create canonical DB folders,
  * back up stray DB files in project root into pyrewall/db/backups/install_migrations/<timestamp>/,
  * create canonical DB files and minimal tables,
  * create a one-time marker file pyrewall/db/first_run.json containing credentials info,
  * create a default admin user (username=admin, password=password) using pyrewall.core.security.create_user()

- If marker exists, returns status 'not_fresh' and marker path info.
"""

import os
import shutil
import sqlite3
import json
import datetime
from pathlib import Path

from pyrewall.db.paths import BASE_DIR, USERS_DB, FIREWALL_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB

MARKER_FILE = os.path.join(BASE_DIR, "first_run.json")
BACKUPS_DIR = os.path.join(BASE_DIR, "backups", "install_migrations")

# default starter credentials (one-time)
DEFAULT_ADMIN = {"username": "admin", "password": "password", "role": "admin"}


def _ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    os.makedirs(os.path.dirname(FIREWALL_DB), exist_ok=True)


def _backup_stray_db_files(project_root=None):
    """
    Move stray top-level DB files (e.g. ./firewall.db) into a time-stamped backup folder.
    Returns dict with info about what was moved.
    """
    project_root = project_root or os.path.abspath(os.path.join(BASE_DIR, ".."))
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target = os.path.join(BACKUPS_DIR, ts)
    moved = []
    try:
        os.makedirs(target, exist_ok=True)
        # consider common stray filenames at project root
        candidates = ["firewall.db", "users.db", "general_history.db", "firewall_logs.db"]
        for name in candidates:
            src = os.path.join(project_root, name)
            if os.path.exists(src) and os.path.isfile(src):
                try:
                    shutil.move(src, os.path.join(target, name))
                    moved.append(name)
                except Exception:
                    # keep going
                    pass
    except Exception:
        pass
    return {"moved": bool(moved), "moved_files": moved, "folder": target}


def _create_minimal_dbs():
    """Open/create canonical DB files and make minimal tables so other modules can rely on them."""
    # create / touch files and ensure minimal tables exist
    for db in (USERS_DB, FIREWALL_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB):
        if not db:
            continue
        os.makedirs(os.path.dirname(db), exist_ok=True)
        try:
            conn = sqlite3.connect(db, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL;")
            cur = conn.cursor()
            # create minimal tables safely (idempotent)
            if db == USERS_DB:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT NOT NULL,
                        role TEXT DEFAULT 'user'
                    )
                """)
            if db == FIREWALL_DB:
                cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT UNIQUE)")
                cur.execute("CREATE TABLE IF NOT EXISTS firewall_rules (id INTEGER PRIMARY KEY, ip TEXT, port TEXT, protocol TEXT, action TEXT)")
                cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT UNIQUE)")
            if db == GENERAL_HISTORY_DB:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        action TEXT,
                        description TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            if db == FIREWALL_LOGS_DB:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS firewall_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        domain TEXT,
                        action TEXT
                    )
                """)
            conn.commit()
            conn.close()
        except Exception:
            # ignore and continue (preflight later will catch real errors)
            pass


def _create_default_admin():
    """
    Create default admin using secure API (pyrewall.core.security.create_user).
    If creation fails (module not available) we still continue gracefully.
    """
    try:
        from pyrewall.core import security
        # create_user uses secure hashing
        created = security.create_user(DEFAULT_ADMIN["username"], DEFAULT_ADMIN["password"], DEFAULT_ADMIN["role"])
        return {"created": bool(created)}
    except Exception:
        return {"created": False, "error": "security module not available"}


def ensure_fresh_installation():
    """
    Called from main.py early to prepare DBs on first run.
    Returns a dict: {status: "fresh"|"not_fresh", backup: {...}, marker: path, credentials: {...}}
    """
    _ensure_dirs()

    # If marker already exists -> not a fresh run (do nothing)
    if os.path.exists(MARKER_FILE):
        try:
            with open(MARKER_FILE, "r", encoding="utf-8") as f:
                marker = json.load(f)
        except Exception:
            marker = {"note": "invalid_marker"}
        return {"status": "not_fresh", "marker": MARKER_FILE, "marker_data": marker}

    # Marker missing => treat as fresh install
    backup_info = _backup_stray_db_files()
    _create_minimal_dbs()
    admin_info = _create_default_admin()

    # write a marker containing credentials (so login UI can show them once)
    marker_data = {
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "credentials": {
            "username": DEFAULT_ADMIN["username"],
            # WARNING: storing plain password here briefly for UI display only (transient)
            # This file will be reliably removed after the first successful admin login.
            "password": DEFAULT_ADMIN["password"]
        },
        "admin_created": admin_info.get("created", False),
        "backup": backup_info
    }
    try:
        with open(MARKER_FILE, "w", encoding="utf-8") as f:
            json.dump(marker_data, f, indent=2)
    except Exception:
        pass

    return {"status": "fresh", "marker": MARKER_FILE, "marker_data": marker_data, "backup": backup_info}
