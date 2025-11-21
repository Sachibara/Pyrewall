# tools/fix_db_paths_and_defaults.py
import os, io, shutil, re, sys

PROJECT_ROOT = os.path.abspath(os.getcwd())
PYREWALL_DIR = os.path.join(PROJECT_ROOT, "pyrewall")
DB_DIR = os.path.join(PYREWALL_DIR, "db")
PATHS_FILE = os.path.join(DB_DIR, "paths.py")

def ensure_paths_file():
    os.makedirs(DB_DIR, exist_ok=True)
    if os.path.exists(PATHS_FILE):
        print("paths.py exists:", PATHS_FILE)
        return
    content = """# Auto-generated canonical DB paths for pyrewall
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
os.makedirs(BASE_DIR, exist_ok=True)
FIREWALL_DB = os.path.join(BASE_DIR, "firewall.db")
USERS_DB = os.path.join(BASE_DIR, "users.db")
GENERAL_HISTORY_DB = os.path.join(BASE_DIR, "general_history.db")
"""
    with open(PATHS_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print("Created", PATHS_FILE)

def backup_file(p):
    bak = p + ".bak"
    shutil.copy2(p, bak)
    print("Backed up:", p, "->", bak)

def replace_in_file(p, new_text):
    backup_file(p)
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(new_text)

def try_patch_file(path):
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()
    out = src

    changed = False

    # 1) Replace top-level DB constants like DEFAULT_DB = "firewall.db"
    #    with an import if not already importing DEFAULT_DB
    if re.search(r'^\s*DEFAULT_DB\s*=.*["\']firewall\.db["\']', out, re.M):
        out = re.sub(r'^\s*DEFAULT_DB\s*=.*$', "# DEFAULT_DB centralized; now use DEFAULT_DB from pyrewall.db.paths", out, count=1, flags=re.M)
        changed = True

    # 2) Replace literal connect(...) where path is "firewall.db" to DEFAULT_DB
    out_new = re.sub(r'sqlite3\.connect\(\s*["\']firewall\.db["\']\s*\)', "sqlite3.connect(DEFAULT_DB)", out)
    if out_new != out:
        out = out_new
        changed = True

    # 3) Replace DEFAULT_DB references with DEFAULT_DB
    out_new = re.sub(r'\bDB_FIREWALL\b', "DEFAULT_DB", out)
    if out_new != out:
        out = out_new
        changed = True

    # 4) Replace USER_DB assignments to use USERS_DB import (only if present)
    out_new = re.sub(r'USER_DB\s*=\s*.*users\.db.*', "# USER_DB centralized; use USERS_DB from pyrewall.db.paths", out)
    if out_new != out:
        out = out_new
        changed = True

    # 5) Add DEFAULT_DB / USERS_DB import if the file uses DEFAULT_DB but doesn't import it
    if ("DEFAULT_DB" in out or "USERS_DB" in out) and "from pyrewall.db.paths import" not in out:
        # Insert after the first block of imports
        lines = out.splitlines(True)
        ins_at = 0
        for i, L in enumerate(lines[:80]):
            if not (L.strip().startswith("import") or L.strip().startswith("from") or L.strip() == ""):
                ins_at = i
                break
        import_line = "from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB, USERS_DB, GENERAL_HISTORY_DB\n"
        lines.insert(ins_at, import_line)
        out = "".join(lines)
        changed = True

    # 6) Change function defs with db_path="firewall.db" -> db_path=None and insert fallback line
    def repl_def(m):
        fname = m.group(1)
        indent = m.group(2) or ""
        new = f"{indent}def {fname}(db_path=None):\n{indent}    db_path = db_path or DEFAULT_DB\n"
        return new

    out_new = re.sub(r'(^\s*def\s+(\w+)\s*\(\s*db_path\s*=\s*[\'"]firewall\.db[\'"]\s*\)\s*:\s*)', repl_def, out, flags=re.M)
    if out_new != out:
        out = out_new
        changed = True

    # 7) If file uses sqlite3.connect(USERS_DB) replace with sqlite3.connect(USERS_DB)
    out_new = re.sub(r'sqlite3\.connect\(\s*USER_DB\s*\)', "sqlite3.connect(USERS_DB)", out)
    if out_new != out:
        out = out_new
        changed = True

    if changed:
        print("Patching:", path)
        replace_in_file(path, out)
    else:
        print("No changes for:", path)

def scan_and_patch():
    ensure_paths_file()
    # walk pyrewall tree
    for root, dirs, files in os.walk(PYREWALL_DIR):
        for fn in files:
            if fn.endswith(".py"):
                p = os.path.join(root, fn)
                # skip the generated paths.py (we created it)
                if os.path.abspath(p) == os.path.abspath(PATHS_FILE):
                    continue
                try:
                    try_patch_file(p)
                except Exception as e:
                    print("ERROR patching", p, ":", e)

def quick_test():
    print("\n--- Quick DB open test ---")
    try:
        from pyrewall.db.paths import FIREWALL_DB, USERS_DB
        import sqlite3
        print("FIREWALL_DB:", FIREWALL_DB, "exists:", os.path.exists(FIREWALL_DB))
        print("USERS_DB:", USERS_DB, "exists:", os.path.exists(USERS_DB))
        # attempt open/close
        sqlite3.connect(FIREWALL_DB).close()
        sqlite3.connect(USERS_DB).close()
        print("DB open OK")
    except Exception as e:
        print("DB open error:", e)

if __name__ == "__main__":
    scan_and_patch()
    quick_test()
    print("\nDone. Please run your app and capture any remaining errors.")
