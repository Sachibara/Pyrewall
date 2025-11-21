# pyrewall/ui/tabs/overview_tab.py
import os
import sqlite3
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGridLayout, QFrame
from PyQt6.QtGui import QFont

from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB, USERS_DB, GENERAL_HISTORY_DB

class OverviewTab(QWidget):
    """Summary dashboard showing overall system stats."""
    def __init__(self, username):
        super().__init__()
        self.username = username

        layout = QVBoxLayout()
        title = QLabel("📊 System Overview")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        grid = QGridLayout()

        # --- Summary Cards ---
        self.sites_label = QLabel()
        self.rules_label = QLabel()
        self.devices_label = QLabel()
        self.users_label = QLabel()

        for label in [self.sites_label, self.rules_label, self.devices_label, self.users_label]:
            label.setFont(QFont("Segoe UI", 12, QFont.Weight.Medium))
            label.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Raised)
            label.setStyleSheet("background-color:#F6F6F6; padding:12px; border-radius:8px;")

        grid.addWidget(self.sites_label, 0, 0)
        grid.addWidget(self.rules_label, 0, 1)
        grid.addWidget(self.devices_label, 1, 0)
        grid.addWidget(self.users_label, 1, 1)

        layout.addLayout(grid)
        self.setLayout(layout)

        # initial refresh
        self.refresh_summary()

    def _ensure_db_parent(self, db_path):
        """Ensure parent folder exists for a DB path (no-op if invalid)."""
        if not db_path:
            return
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def refresh_summary(self):
        """Count total records from key DBs. Creates missing tables if necessary."""
        try:
            # ensure DB parent exists
            self._ensure_db_parent(DEFAULT_DB)
            self._ensure_db_parent(USERS_DB)

            # Work with firewall DB (blocked_domains + firewall_rules)
            sites = 0
            rules = 0
            try:
                with sqlite3.connect(os.path.abspath(DEFAULT_DB)) as conn:
                    cur = conn.cursor()
                    # ensure expected tables exist (safe no-op if already present)
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS blocked_domains (
                            domain TEXT UNIQUE
                        )
                    """)
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS firewall_rules (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT,
                            port TEXT,
                            protocol TEXT,
                            action TEXT
                        )
                    """)
                    # count
                    cur.execute("SELECT COUNT(*) FROM blocked_domains")
                    sites = cur.fetchone()[0] or 0

                    cur.execute("SELECT COUNT(*) FROM firewall_rules")
                    rules = cur.fetchone()[0] or 0
            except Exception as db_e:
                # if firewall DB can't be opened or queried, show partial info below
                self.sites_label.setText(f"Error loading sites: {db_e}")
                self.rules_label.setText(f"Error loading rules: {db_e}")
                # still attempt users count

            # Users DB count
            users = 0
            try:
                with sqlite3.connect(os.path.abspath(USERS_DB)) as conn2:
                    cur2 = conn2.cursor()
                    cur2.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password TEXT NOT NULL,
                            role TEXT DEFAULT 'user'
                        )
                    """)
                    cur2.execute("SELECT COUNT(*) FROM users")
                    users = cur2.fetchone()[0] or 0
            except Exception as user_e:
                self.users_label.setText(f"Error loading users: {user_e}")

            # Fill labels (only override if not set to error above)
            if not self.sites_label.text().startswith("Error"):
                self.sites_label.setText(f"🌐 Blocked Websites: {sites}")
            if not self.rules_label.text().startswith("Error"):
                self.rules_label.setText(f"🛡️ Firewall Rules: {rules}")
            # devices are detected live by other tab; we keep an explanatory note
            self.devices_label.setText("📡 Detected Devices: Live scan only")
            if not self.users_label.text().startswith("Error"):
                self.users_label.setText(f"👥 Registered Users: {users}")

        except Exception as e:
            # Catch-all fallback so the UI doesn't crash
            self.sites_label.setText(f"Error loading stats: {e}")
            self.rules_label.setText("🛡️ Firewall Rules: error")
            self.devices_label.setText("📡 Detected Devices: error")
            self.users_label.setText("👥 Registered Users: error")
