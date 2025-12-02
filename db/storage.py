# pyrewall/db/storage.py
"""
Database storage helpers for Pyrewall.

This module uses canonical DB paths from pyrewall.db.paths and
ensures directories exist before any sqlite3 connections are attempted.
"""

import os
import sqlite3
from datetime import datetime
from typing import Optional

from pyrewall.db.paths import USERS_DB, GENERAL_HISTORY_DB

# Helper to ensure parent directory exists before opening DB
def _ensure_db_parent(db_path: str):
    if not db_path:
        return
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

# ============================================================
# 1) USER DATABASE INITIALIZATION AND ROLE HANDLING
# ============================================================
def init_user_db():
    """Ensure user database and tables exist, create default admin if missing."""
    _ensure_db_parent(USERS_DB)
    conn = sqlite3.connect(os.path.abspath(USERS_DB))
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)

    # Create default admin account if missing (only if no 'admin' user)
    cur.execute("SELECT username FROM users WHERE username = 'admin' LIMIT 1")
    if not cur.fetchone():
        # Note: password hashing should be used in production; this keeps compatibility
        cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", "admin123", "admin"))
        print("[Pyrewall] ✅ Default admin created (username: admin / password: admin123)")

    conn.commit()
    conn.close()

def ensure_user_table_with_roles():
    """Ensures the 'users' table has the 'role' column, adds it if missing."""
    try:
        _ensure_db_parent(USERS_DB)
        conn = sqlite3.connect(os.path.abspath(USERS_DB))
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cur.fetchall()]
        if "role" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            conn.commit()
            print("[Pyrewall] ✅ Added missing 'role' column to users table.")
        conn.close()
    except Exception as e:
        print(f"[Pyrewall] Database role column check failed: {e}")

# ============================================================
# 2) USER VERIFICATION AND MANAGEMENT
# ============================================================
def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify login credentials and return role if valid."""
    try:
        _ensure_db_parent(USERS_DB)
        conn = sqlite3.connect(os.path.abspath(USERS_DB))
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users WHERE username = ? AND password = ?", (username, password))
        user = cur.fetchone()
        conn.close()
        if user:
            return {"username": user[0], "role": user[1]}
        return None
    except Exception as e:
        print(f"[Pyrewall] verify_user() error: {e}")
        return None

def add_user(username: str, password: str, role: str = "user"):
    """Add a new user (admin-only function)."""
    try:
        _ensure_db_parent(USERS_DB)
        conn = sqlite3.connect(os.path.abspath(USERS_DB))
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, password, role))
        conn.commit()
        conn.close()
        print(f"[Pyrewall] Added user: {username} ({role})")
    except Exception as e:
        print(f"[Pyrewall] add_user() error: {e}")

def remove_user(username: str):
    """Remove a user (admin-only function)."""
    try:
        _ensure_db_parent(USERS_DB)
        conn = sqlite3.connect(os.path.abspath(USERS_DB))
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        print(f"[Pyrewall] Removed user: {username}")
    except Exception as e:
        print(f"[Pyrewall] remove_user() error: {e}")

def list_users():
    """Return list of all users."""
    try:
        _ensure_db_parent(USERS_DB)
        conn = sqlite3.connect(os.path.abspath(USERS_DB))
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users")
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"[Pyrewall] list_users() error: {e}")
        return []

# ============================================================
# 3) ACTIVITY LOGGING (GENERAL HISTORY)
# ============================================================
def init_history_db():
    """Ensure general_history database and table exist."""
    _ensure_db_parent(GENERAL_HISTORY_DB)
    conn = sqlite3.connect(os.path.abspath(GENERAL_HISTORY_DB))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def log_general_history(username: str, action: str, description: str):
    """Log any user/system action into the general_history database."""
    try:
        _ensure_db_parent(GENERAL_HISTORY_DB)
        conn = sqlite3.connect(os.path.abspath(GENERAL_HISTORY_DB))
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute(
            "INSERT INTO history (username, action, description) VALUES (?, ?, ?)",
            (username, action, description)
        )
        conn.commit()
        conn.close()
        print(f"[LOG] {username} -> {action}: {description}")
    except Exception as e:
        print(f"[LOG ERROR] Failed to write history: {e}")
