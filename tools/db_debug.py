# pyrewall/tools/db_debug.py
"""
Lightweight debug to verify the canonical DB files referenced by pyrewall.db.paths
This script intentionally uses the absolute paths provided by the package (no rebasing).
It will create parent directories if missing and attempt to open each DB to ensure
SQLite can create/open them.
"""

import sqlite3
import os
import sys
from pathlib import Path

# Import canonical paths from package
try:
    from pyrewall.db import paths as p
except Exception as e:
    print("ERROR: failed to import pyrewall.db.paths ->", type(e).__name__, e)
    print("Make sure you're running this from your project root and the package is importable.")
    sys.exit(2)


def try_open_db(db_path: str):
    print("Checking:", db_path)
    # Ensure parent dir exists
    parent = os.path.dirname(db_path)
    if not parent:
        print("  WARNING: db path has no parent directory:", db_path)
        return False
    try:
        os.makedirs(parent, exist_ok=True)
    except Exception as e:
        print("  FAILED to create parent dir:", parent, "->", e)
        return False

    # Try to open (this will create the file if possible)
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.close()
        exists = os.path.exists(db_path)
        print("  OPEN OK. Exists now?:", exists)
        return True
    except sqlite3.OperationalError as oe:
        print("  OPEN ERROR ->", oe)
        return False
    except Exception as e:
        print("  OPEN ERROR ->", type(e).__name__, e)
        return False


def main():
    print("Project root (cwd):", os.getcwd())
    print("Using canonical paths from pyrewall.db.paths\n")

    # Show values
    print("USERS_DB:", p.USERS_DB)
    print("FIREWALL_DB:", p.FIREWALL_DB)
    print("GENERAL_HISTORY_DB:", getattr(p, "GENERAL_HISTORY_DB", "<missing>"))
    print("FIREWALL_LOGS_DB:", getattr(p, "FIREWALL_LOGS_DB", "<missing>"))
    print()

    all_paths = []
    for attr in ("USERS_DB", "FIREWALL_DB", "GENERAL_HISTORY_DB", "FIREWALL_LOGS_DB"):
        dbp = getattr(p, attr, None)
        if dbp:
            all_paths.append(dbp)

    any_fail = False
    for path in all_paths:
        ok = try_open_db(path)
        if not ok:
            any_fail = True

    if any_fail:
        print("\nOne or more DB paths failed to open. Please check permissions and that the paths above are correct.")
        sys.exit(1)
    else:
        print("\nAll DB paths opened successfully.")

if __name__ == "__main__":
    main()
