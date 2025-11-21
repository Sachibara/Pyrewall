# pyrewall/core/security.py
"""
Secure password and user management utilities for Pyrewall.

🔥 Critical Security Fix:
Replaces plaintext password storage with PBKDF2-HMAC-SHA256 hashes.

Stored password format:
    iterations$salt_hex$hash_hex

Example:
    150000$3d2a8f74e3aa6b53bc22b37b17de92b1$3f4c6f2e...

Functions:
    - hash_password(password) -> str
    - verify_password(stored_hash, password) -> bool
    - create_user(username, password, role="user", db_path=DB_PATH)
    - set_password(username, password, db_path=DB_PATH)
    - validate_user(username, password, db_path=DB_PATH)
    - is_admin(username, db_path=DB_PATH)

All users are stored in: pyrewall/db/users.db
"""

import os
import sqlite3
import hashlib
import hmac
from typing import Optional

# ============================================================
# CONFIGURATION
# ============================================================

# Always point to the canonical DB inside the project package
from pyrewall.db.paths import USERS_DB as DB_PATH
# remove any os.makedirs(...) for DB_PATH directory (paths.py already ensures it)

PBKDF2_ITERATIONS = 150_000  # recommended default
SALT_BYTES = 16
HASH_NAME = "sha256"


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _ensure_user_table():
    """Create 'users' table if missing, with secure default role."""
    # make sure the directory exists (prevents sqlite 'unable to open database file')
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(os.path.abspath(DB_PATH))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    # Ensure 'role' column exists in older DBs
    cur.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cur.fetchall()]
    if "role" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        conn.commit()
    conn.commit()
    conn.close()



# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash in the format iterations$salt$hash."""
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, iterations)
    return f"{iterations}${salt.hex()}${dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    """Verify a plaintext password against stored PBKDF2 format."""
    try:
        parts = stored.split("$")
        if len(parts) != 3:
            return False
        iterations = int(parts[0])
        salt = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
        derived = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(expected, derived)
    except Exception:
        return False


# ============================================================
# USER MANAGEMENT
# ============================================================

def create_user(username: str, password: str, role: str = "user", db_path: Optional[str] = None) -> bool:
    """
    Create a new user with hashed password.
    Returns True if user created successfully, False if user already exists.
    """
    dpath = db_path or DB_PATH
    _ensure_user_table()
    hashed = hash_password(password)

    conn = sqlite3.connect(dpath)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def set_password(username: str, password: str, db_path: Optional[str] = None) -> bool:
    """Change an existing user's password (re-hash new one)."""
    dpath = db_path or DB_PATH
    _ensure_user_table()
    hashed = hash_password(password)

    conn = sqlite3.connect(dpath)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed > 0


def validate_user(username: str, password: str, db_path: Optional[str] = None) -> bool:
    """Return True if username exists and password matches."""
    dpath = db_path or DB_PATH
    _ensure_user_table()

    conn = sqlite3.connect(dpath)
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False
    stored = row[0]
    return verify_password(stored, password)


def is_admin(username: str, db_path: Optional[str] = None) -> bool:
    """Check if user has admin role."""
    dpath = db_path or DB_PATH
    _ensure_user_table()

    conn = sqlite3.connect(dpath)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    return bool(row and str(row[0]).lower() == "admin")


# ============================================================
# UTILITIES
# ============================================================

def ensure_default_admin():
    """
    Create a default admin account if none exists.
    ⚠️ Only runs when the DB is first initialized.
    """
    _ensure_user_table()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    if cur.fetchone()[0] == 0:
        print("[Pyrewall] 🛠️ Creating default admin account: admin / admin")
        admin_hash = hash_password("admin")
        cur.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", admin_hash, "admin"))
        conn.commit()
    conn.close()


# ============================================================
# INIT
# ============================================================

# Ensure DB structure and admin presence at import time
_ensure_user_table()
ensure_default_admin()
