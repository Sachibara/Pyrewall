# pyrewall/tools/db_debug.py
"""
Robust DB debug/creator.
Will use pyrewall/db/paths.py canonical constants and create the DB files if needed.
Works regardless of whether you run it from project root or from inside the pyrewall package.
"""

import os, sys, sqlite3
from pathlib import Path
import importlib

def load_paths_module():
    # Prefer normal import first (clean environment)
    try:
        import pyrewall.db.paths as p
        return p
    except Exception:
        # Fallback: locate file relative to this script in case sys.path is different
        this_file = Path(__file__).resolve()
        # expected file: <project>/pyrewall/db/paths.py
        candidate = this_file.parent.parent / "db" / "paths.py"
        if not candidate.exists():
            raise RuntimeError(f"Cannot find pyrewall/db/paths.py at expected location: {candidate}")
        # load module from file path
        import importlib.util
        spec = importlib.util.spec_from_file_location("pyrewall.db.paths", str(candidate))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

def try_open_db(db_path):
    print("Checking:", db_path)
    parent = os.path.dirname(db_path)
    if not parent:
        print("  BAD PATH (no parent):", db_path)
        return False
    try:
        os.makedirs(parent, exist_ok=True)
    except Exception as e:
        print("  FAILED to create parent dir:", parent, "->", e)
        return False
    try:
        conn = sqlite3.connect(db_path)
        # small safety PRAGMA to ensure file created and writable
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.close()
        print("  OPEN OK. Exists now?:", os.path.exists(db_path))
        return True
    except sqlite3.OperationalError as oe:
        print("  OPEN ERROR ->", oe)
        return False
    except Exception as e:
        print("  OPEN ERROR ->", type(e).__name__, e)
        return False

def main():
    print("Working dir:", os.getcwd())
    print("Loading canonical paths from pyrewall/db/paths.py")
    p = load_paths_module()
    # print values
    print("USERS_DB:", getattr(p, "USERS_DB", "<missing>"))
    print("FIREWALL_DB:", getattr(p, "FIREWALL_DB", "<missing>"))
    print("GENERAL_HISTORY_DB:", getattr(p, "GENERAL_HISTORY_DB", "<missing>"))
    print("FIREWALL_LOGS_DB:", getattr(p, "FIREWALL_LOGS_DB", "<missing>"))
    print()

    all_paths = [getattr(p, attr) for attr in ("USERS_DB", "FIREWALL_DB", "GENERAL_HISTORY_DB", "FIREWALL_LOGS_DB") if hasattr(p, attr)]

    any_fail = False
    for db in all_paths:
        ok = try_open_db(db)
        if not ok:
            any_fail = True

    if any_fail:
        print("\nFAILED: one or more DBs could not be opened/created.")
        sys.exit(1)
    print("\nSUCCESS: all DBs opened or created correctly.")

if __name__ == "__main__":
    main()
