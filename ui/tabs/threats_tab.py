import os
import sqlite3
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton, QHBoxLayout, QMessageBox
from PyQt6.QtGui import QFont
from pyrewall.ui.button_styles import make_button

DB_PATH = "pyrewall/db/threats.db"


class ThreatsTab(QWidget):
    """Displays detected threats, suspicious traffic, and IDS/IPS alerts."""
    def __init__(self, username):
        super().__init__()
        self.username = username

        layout = QVBoxLayout()
        title = QLabel("🚨 Intrusion Detection & Threat Monitoring")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # --- Control buttons ---
        button_layout = QHBoxLayout()
        refresh_btn = make_button("🔄 Refresh Alerts", variant="primary", height=28)
        clear_btn = make_button("🧹 Clear All Alerts", variant="danger", height=28)
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(clear_btn)

        layout.addLayout(button_layout)

        # --- Threat list ---
        self.alert_list = QListWidget()
        layout.addWidget(self.alert_list)

        self.setLayout(layout)
        self._init_db()
        self.load_alerts()

        # --- Signals ---
        refresh_btn.clicked.connect(self.load_alerts)
        clear_btn.clicked.connect(self.clear_alerts)

    # ====================================================
    # 🧱 DATABASE HANDLING
    # ====================================================
    def _init_db(self):
        """Ensure threats table exists."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    severity TEXT,
                    description TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to initialize threats DB:\n{e}")

    # ====================================================
    # 🔄 LOAD ALERTS
    # ====================================================
    def load_alerts(self):
        """Fetch and display recent IDS/IPS alerts."""
        self.alert_list.clear()
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, src_ip, dst_ip, protocol, severity, description
                FROM threats ORDER BY id DESC LIMIT 100
            """)
            alerts = cur.fetchall()
            conn.close()

            if not alerts:
                self.alert_list.addItem("(No detected threats yet.)")
                return

            for ts, src, dst, proto, sev, desc in alerts:
                line = f"[{ts}] ({sev}) {proto} {src} ➜ {dst} — {desc}"
                self.alert_list.addItem(line)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load alerts:\n{e}")

    # ====================================================
    # 🧹 CLEAR ALERTS
    # ====================================================
    def clear_alerts(self):
        """Clear all IDS/IPS alerts (admin only)."""
        confirm = QMessageBox.question(self, "Confirm", "Are you sure you want to delete all threat alerts?")
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("DELETE FROM threats")
            conn.commit()
            conn.close()
            self.load_alerts()
            QMessageBox.information(self, "Cleared", "All threat alerts cleared.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to clear alerts:\n{e}")
