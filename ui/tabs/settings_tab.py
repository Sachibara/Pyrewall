# pyrewall/ui/tabs/settings_tab.py
import os
import json
import shutil
import datetime
import sys
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QCheckBox, QPushButton, QMessageBox, QHBoxLayout, QApplication
)
from PyQt6.QtGui import QFont

# canonical DB paths and base dir
from pyrewall.db.paths import BASE_DIR, USERS_DB, FIREWALL_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB

# optional imports we will try to use
try:
    from pyrewall.core.firewall_thread import notify_firewall_reload
except Exception:
    notify_firewall_reload = None

# logger_core allows toggling logging level at runtime
try:
    from pyrewall.core.logger_core import system_logger, firewall_logger, alert_logger
except Exception:
    system_logger = firewall_logger = alert_logger = None

SETTINGS_DIR = os.path.join(BASE_DIR, "config")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
DB_BACKUP_DIR = os.path.join(os.path.dirname(FIREWALL_DB), "backups")  # pyrewall/db/backups

DEFAULT_SETTINGS = {
    "auto_start": False,
    "detailed_logging": False,
    "dark_mode": False,
    "dns_proxy_enabled": True,
    "create_netsh_blocks": True
}


class SettingsTab(QWidget):
    """General settings + actions. Settings persist to pyrewall/db/config/settings.json"""

    def __init__(self, username):
        super().__init__()
        self.username = username

        self._ensure_dirs()
        self.settings = self._load_settings()

        layout = QVBoxLayout()
        title = QLabel("⚙️ Application Settings")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # checkboxes
        self.auto_start_checkbox = QCheckBox("Start firewall automatically on launch")
        self.log_network_checkbox = QCheckBox("Enable detailed network logging (increase log verbosity)")
        self.dark_mode_checkbox = QCheckBox("Enable dark mode (UI theme)")

        # optional feature toggles
        self.dns_proxy_checkbox = QCheckBox("Enable built-in DNS proxy")
        self.netsh_checkbox = QCheckBox("Use netsh for IP blocks (Windows)")

        for cb in (self.auto_start_checkbox, self.log_network_checkbox, self.dark_mode_checkbox,
                   self.dns_proxy_checkbox, self.netsh_checkbox):
            layout.addWidget(cb)

        # load values into UI and apply immediately where reasonable
        self._apply_settings_to_ui(self.settings)
        self._apply_runtime_settings(self.settings)

        # Save / Reset buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton("💾 Save Settings")
        reset_btn = QPushButton("♻️ Reset to Defaults")
        btn_row.addWidget(save_btn)
        btn_row.addWidget(reset_btn)
        layout.addLayout(btn_row)

        save_btn.clicked.connect(self.save_settings)
        reset_btn.clicked.connect(self.reset_to_defaults)

        # Additional management actions
        mgmt_row = QHBoxLayout()
        self.reload_lists_btn = QPushButton("🔁 Reload Firewall Lists")
        self.backup_dbs_btn = QPushButton("📦 Backup DBs")
        self.open_db_folder_btn = QPushButton("📂 Open DB Folder")
        mgmt_row.addWidget(self.reload_lists_btn)
        mgmt_row.addWidget(self.backup_dbs_btn)
        mgmt_row.addWidget(self.open_db_folder_btn)
        layout.addLayout(mgmt_row)

        self.reload_lists_btn.clicked.connect(self.reload_firewall_lists)
        self.backup_dbs_btn.clicked.connect(self.backup_databases)
        self.open_db_folder_btn.clicked.connect(self.open_db_folder)

        # small note
        note = QLabel(f"Tip: Backups are stored under {DB_BACKUP_DIR} (timestamped folders).")
        layout.addWidget(note)

        self.setLayout(layout)

    # -------------------------
    # Filesystem / persistence
    # -------------------------
    def _ensure_dirs(self):
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            os.makedirs(DB_BACKUP_DIR, exist_ok=True)
            os.makedirs(os.path.dirname(FIREWALL_DB), exist_ok=True)
        except Exception:
            pass

    def _load_settings(self):
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                merged = DEFAULT_SETTINGS.copy()
                merged.update({k: data.get(k, merged[k]) for k in merged.keys()})
                return merged
        except Exception:
            pass
        return DEFAULT_SETTINGS.copy()

    def _apply_settings_to_ui(self, settings: dict):
        self.auto_start_checkbox.setChecked(bool(settings.get("auto_start", False)))
        self.log_network_checkbox.setChecked(bool(settings.get("detailed_logging", False)))
        self.dark_mode_checkbox.setChecked(bool(settings.get("dark_mode", False)))
        self.dns_proxy_checkbox.setChecked(bool(settings.get("dns_proxy_enabled", True)))
        self.netsh_checkbox.setChecked(bool(settings.get("create_netsh_blocks", True)))

    def _gather_ui_settings(self) -> dict:
        return {
            "auto_start": bool(self.auto_start_checkbox.isChecked()),
            "detailed_logging": bool(self.log_network_checkbox.isChecked()),
            "dark_mode": bool(self.dark_mode_checkbox.isChecked()),
            "dns_proxy_enabled": bool(self.dns_proxy_checkbox.isChecked()),
            "create_netsh_blocks": bool(self.netsh_checkbox.isChecked()),
        }

    # -------------------------
    # Apply runtime changes
    # -------------------------
    def _apply_runtime_settings(self, settings: dict):
        # set logging level if logger_core is available
        if system_logger:
            level = "INFO"
            if settings.get("detailed_logging"):
                level = "DEBUG"
            numeric = getattr(__import__("logging"), level)
            for lg in (system_logger, firewall_logger, alert_logger):
                if lg:
                    lg.setLevel(numeric)

        # apply dark mode (very simple stylesheet)
        try:
            if settings.get("dark_mode"):
                qapp = QApplication.instance()
                if qapp:
                    qapp.setStyleSheet("""
                        QWidget { background: #222; color: #ddd; }
                        QPushButton { background: #333; color: #fff; border-radius:6px; padding:6px; }
                        QLineEdit, QTextEdit { background: #2b2b2b; color: #fff; }
                    """)
            else:
                qapp = QApplication.instance()
                if qapp:
                    qapp.setStyleSheet("")
        except Exception:
            pass

    # -------------------------
    # Actions
    # -------------------------
    def save_settings(self):
        try:
            cfg = self._gather_ui_settings()
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            # apply immediately
            self._apply_runtime_settings(cfg)

            # handle auto-start entry: create/remove startup script
            if cfg.get("auto_start"):
                ok, msg = self._create_startup_entry()
            else:
                ok, msg = self._remove_startup_entry()

            QMessageBox.information(self, "Settings Saved", f"✅ Preferences saved.\n{msg}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save settings: {e}")

    def reset_to_defaults(self):
        reply = QMessageBox.question(
            self, "Reset to Defaults",
            "This will remove your saved preferences and restore defaults. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            if os.path.exists(SETTINGS_FILE):
                os.remove(SETTINGS_FILE)
            self.settings = DEFAULT_SETTINGS.copy()
            self._apply_settings_to_ui(self.settings)
            self._apply_runtime_settings(self.settings)
            # remove startup entry too
            self._remove_startup_entry()
            QMessageBox.information(self, "Reset", "✅ Settings reset to defaults.")
        except Exception as e:
            QMessageBox.critical(self, "Reset Error", f"Could not reset settings: {e}")

    def reload_firewall_lists(self):
        if notify_firewall_reload is None:
            QMessageBox.warning(self, "Reload Not Available",
                                "The running firewall thread is not accessible from this process.")
            return
        try:
            notify_firewall_reload()
            QMessageBox.information(self, "Reload Requested", "✅ Firewall thread notified to reload lists.")
        except Exception as e:
            QMessageBox.critical(self, "Reload Error", f"Failed to notify firewall thread: {e}")

    def backup_databases(self):
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target = os.path.join(DB_BACKUP_DIR, timestamp)
            os.makedirs(target, exist_ok=True)

            copied = []
            for db in (FIREWALL_DB, USERS_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB):
                if not db:
                    continue
                try:
                    src = os.path.abspath(db)
                    if os.path.exists(src):
                        shutil.copy2(src, target)
                        copied.append(os.path.basename(src))
                except Exception:
                    pass

            if copied:
                QMessageBox.information(self, "Backup Complete", f"✅ Backed up: {', '.join(copied)}\nFolder: {target}")
            else:
                QMessageBox.warning(self, "Backup", "No database files were found to back up.")
        except Exception as e:
            QMessageBox.critical(self, "Backup Failed", f"Backup failed: {e}")

    def open_db_folder(self):
        folder = os.path.abspath(os.path.dirname(FIREWALL_DB))
        try:
            if os.name == "nt":
                os.startfile(folder)
            elif shutil.which("xdg-open"):
                __import__("subprocess").call(["xdg-open", folder])
            elif shutil.which("open"):
                __import__("subprocess").call(["open", folder])
            else:
                QMessageBox.information(self, "Open Folder", folder)
        except Exception as e:
            QMessageBox.critical(self, "Open Failed", f"Could not open folder: {e}")

    # -------------------------
    # Windows autostart helpers (safe fallback using a simple .bat in Startup)
    # -------------------------
    def _get_startup_script_path(self):
        # Return path to the startup script we will create for auto-start on Windows
        if os.name != "nt":
            return None
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return None
        startup_dir = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        os.makedirs(startup_dir, exist_ok=True)
        # script name unique to this project
        return os.path.join(startup_dir, "pyrewall_startup.bat")

    def _create_startup_entry(self):
        """Create a small .bat that launches the project on user login (Windows)."""
        if os.name != "nt":
            return False, "Auto-start is only implemented for Windows in this build."
        script = self._get_startup_script_path()
        if not script:
            return False, "Could not locate Startup folder."

        # Choose python executable and module path
        python_exe = sys.executable or "python"
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        # create safe command to run the module
        cmd = f'@"{python_exe}" -m pyrewall.main\n'
        try:
            with open(script, "w", encoding="utf-8") as f:
                f.write(cmd)
            return True, f"Auto-start enabled (script created: {script})"
        except Exception as e:
            return False, f"Failed to create startup script: {e}"

    def _remove_startup_entry(self):
        if os.name != "nt":
            return False, "Auto-start removal only supported on Windows in this build."
        script = self._get_startup_script_path()
        try:
            if script and os.path.exists(script):
                os.remove(script)
                return True, "Auto-start disabled (startup script removed)."
            return True, "No startup script found; nothing to remove."
        except Exception as e:
            return False, f"Failed to remove startup script: {e}"
