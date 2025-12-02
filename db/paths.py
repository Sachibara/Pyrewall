# pyrewall/db/paths.py
import os
import shutil
import sys

# Allow explicit override (handy for testing/CI)
env_dir = os.environ.get("PYREWALL_DB_DIR")
if env_dir:
    BASE_DIR = os.path.abspath(env_dir)
else:
    # When running as a frozen app (PyInstaller onefile/onedir), use LocalAppData for writable runtime DBs
    if getattr(sys, "frozen", False):
        local_appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        BASE_DIR = os.path.join(local_appdata, "Pyrewall", "db")
    else:
        # Dev mode: keep DBs inside package folder for convenience
        BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))

# Ensure runtime dir exists
os.makedirs(BASE_DIR, exist_ok=True)

# Packaged resource DB path (inside bundle this becomes sys._MEIPASS/db if added with PyInstaller)
def _packaged_db_dir():
    if getattr(sys, "frozen", False):
        return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)), "db")
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "db"))

_PACKAGED_DB_DIR = _packaged_db_dir()

# Canonical runtime DB filenames (keep all inside BASE_DIR)
USERS_DB = os.path.join(BASE_DIR, "users.db")
FIREWALL_DB = os.path.join(BASE_DIR, "firewall.db")
GENERAL_HISTORY_DB = os.path.join(BASE_DIR, "general_history.db")
FIREWALL_LOGS_DB = os.path.join(BASE_DIR, "firewall_logs.db")

# If packaged DB template exists, copy it on first run so runtime uses writable files.
def _ensure_db_from_package(filename):
    dest = os.path.join(BASE_DIR, filename)
    if os.path.exists(dest):
        return
    packaged = os.path.join(_PACKAGED_DB_DIR, filename)
    try:
        if os.path.exists(packaged):
            shutil.copy2(packaged, dest)
        else:
            # Create empty sqlite file as best-effort fallback
            open(dest, "a").close()
    except Exception:
        # best-effort only; don't raise at import time
        pass

for _f in ("users.db", "firewall.db", "general_history.db", "firewall_logs.db"):
    _ensure_db_from_package(_f)

__all__ = [
    "BASE_DIR",
    "USERS_DB",
    "FIREWALL_DB",
    "GENERAL_HISTORY_DB",
    "FIREWALL_LOGS_DB",
]
