# pyrewall/main.py
import sys
import os
import atexit
from PyQt6.QtWidgets import QApplication, QLabel
from typing import Optional, Callable, Any

# Controller API placeholders (will be set by import below)
start_firewall: Optional[Callable[..., Any]] = None
stop_firewall: Optional[Callable[..., Any]] = None
is_firewall_running: Optional[Callable[[], bool]] = None
is_firewall_ready: Optional[Callable[[], bool]] = None


# Ensure Python can find all pyrewall packages
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# add bundled DLL directory (Windows only)
if sys.platform.startswith("win"):
    dll_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "dll")
    if os.path.isdir(dll_dir):
        try:
            sys.path.insert(0, dll_dir)
            sys.add_dll_directory(dll_dir)  # python 3.8+ on Windows
        except Exception:
            # fallback: also add to PATH so ctypes can find it
            os.environ["PATH"] += os.pathsep + dll_dir

# installer import (safe to import early; we won't run it until main)
try:
    from pyrewall.db import install as install_module
except Exception:
    install_module = None

# NOTE: DO NOT import UI modules or firewall_thread here.
# They may use DB files at import time. Import them later in main()
# after DBs have been created/validated.

# Path to an installer-complete marker (persisted to the DB folder)
from pyrewall.db.paths import BASE_DIR as PYREWALL_DB_DIR
_INSTALL_MARKER = os.path.join(PYREWALL_DB_DIR, ".install_complete")

def _is_install_done() -> bool:
    """Return True if installer already ran successfully on this machine (marker file present)."""
    try:
        return os.path.exists(_INSTALL_MARKER)
    except Exception:
        return False

def _write_install_marker():
    """Write a small marker so future runs won't reinitialize DBs."""
    try:
        with open(_INSTALL_MARKER, "w", encoding="utf-8") as f:
            f.write("installed\n")
        # try to hide on Windows (best-effort)
        if os.name == "nt":
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(_INSTALL_MARKER, FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass
    except Exception:
        pass
# -------------------------------------------------------------------------

def main():
    fw = None
    LoginPage = None
    # DO NOT shadow the module-level placeholders by reassigning them here.
    # Module-level placeholders (declared earlier) will serve as the fallback (None)
    # if importing the controller fails below.

    # ----- Fresh-install check: detect moved installation and reinit DBs (run only once) -----
    try:
        if install_module and not _is_install_done():
            result = install_module.ensure_fresh_installation()
            if isinstance(result, dict) and result.get("status") == "fresh":
                print("[Pyrewall] Fresh install detected on this machine. DBs reinitialized.")
                if result.get("backup", {}).get("moved"):
                    print(f"[Pyrewall] Existing DBs were backed up to: {result.get('backup', {}).get('folder')}")
            else:
                print("[Pyrewall] install_module.ensure_fresh_installation() completed.")
            _write_install_marker()
    except Exception as e:
        print("[Pyrewall] Install check failed:", e)

    # ----- DB preflight: ensure canonical DBs exist & are writable -----
    import sqlite3
    pkg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "db"))
    os.makedirs(pkg_dir, exist_ok=True)
    canonical_db = os.path.abspath(os.path.join(pkg_dir, "firewall.db"))
    users_db = os.path.abspath(os.path.join(pkg_dir, "users.db"))
    print("[Pyrewall] canonical DB path:", canonical_db)
    print("[Pyrewall] users DB path:", users_db)

    try:
        for p in (canonical_db, users_db):
            conn = sqlite3.connect(p, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS __pyrewall_test (id INTEGER PRIMARY KEY)")
            conn.execute("DROP TABLE IF EXISTS __pyrewall_test")
            conn.commit()
            conn.close()
        print("[Pyrewall] ✅ DB preflight successful — files accessible.")
    except Exception as e:
        print("[Pyrewall] ❌ DB preflight error (cannot open/create DB):", e)
        raise

    # ------- NOW SAFE TO IMPORT UI and controller modules -------
    try:
        from pyrewall.ui.login import LoginPage
    except Exception as e:
        print("ui.login not ready yet:", e)
        LoginPage = None

    try:
        # Import controller API into the function local namespace.
        # If this import fails, the module-level placeholders (declared at top of file)
        # remain as None and your UI will handle absence gracefully.
        from pyrewall.core.firewall_thread import start_firewall, stop_firewall, is_firewall_running, is_firewall_ready
    except Exception as e:
        # Do not reassign to None here – use the module-level defaults instead
        print("core.firewall_thread not ready:", e)
    # ------------------------------------------------------------------

    # ensure graceful stop on exit
    def _cleanup():
        """Best-effort stop of the firewall when the app exits."""
        try:
            # stop_firewall here refers to the controller function imported above,
            # if the import failed it will be None.
            if callable(stop_firewall):
                stop_firewall(wait=False, timeout=2.0)
        except Exception:
            pass

    atexit.register(_cleanup)

    app = QApplication(sys.argv)
    if LoginPage:
        win = LoginPage()
        win.show()
    else:
        from PyQt6.QtWidgets import QWidget, QVBoxLayout
        win = QWidget()
        layout = QVBoxLayout()
        label = QLabel("✅ Pyrewall project is running.\n(ui.login not implemented yet)")
        layout.addWidget(label)
        win.setLayout(layout)
        win.setWindowTitle("Pyrewall Test Window")
        win.resize(400, 200)
        win.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
