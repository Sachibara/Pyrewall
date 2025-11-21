import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton,
    QHBoxLayout, QMessageBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import QTimer
from datetime import datetime, timedelta

DB_PATH = "pyrewall/db/general_history.db"


class HistoryTab(QWidget):
    """Displays system actions and event logs in real-time."""
    def __init__(self, username, role="user"):
        super().__init__()
        self.username = username
        self.role = role.lower().strip() if role else "user"
        self.last_count = 0

        # ---------- UI Setup ----------
        layout = QVBoxLayout()
        title = QLabel("📜 Logs & Activity History")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Buttons (Admin-only)
        button_layout = QHBoxLayout()
        if self.role == "admin":
            self.clear_btn = QPushButton("🧹 Clear Old Logs")
            self.clear_btn.setStyleSheet("""
                QPushButton {
                    background-color: #dc3545;
                    color: white;
                    font-weight: bold;
                    border-radius: 6px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #c82333;
                }
            """)
            self.clear_btn.clicked.connect(self.clear_old_logs)
            button_layout.addWidget(self.clear_btn)

        layout.addLayout(button_layout)

        # Log list
        self.log_list = QListWidget()
        self.log_list.setStyleSheet("""
            QListWidget {
                background-color: #f9f9f9;
                border: 1px solid #ccc;
                border-radius: 8px;
                padding: 6px;
            }
        """)
        layout.addWidget(self.log_list)
        self.setLayout(layout)

        # ---------- Initialization ----------
        self._init_db()
        self.load_logs(first=True)

        # ---------- Timer for Instant Updates ----------
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_for_updates)
        self.timer.start(1000)  # every 1 second

    # ==========================================================
    # Database Setup
    # ==========================================================
    def _init_db(self):
        """Ensure general_history table exists."""
        try:
            conn = sqlite3.connect(DB_PATH)
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
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to init history DB:\n{e}")

    # ==========================================================
    # Auto Refresh Functions
    # ==========================================================
    def check_for_updates(self):
        """Instantly refresh when a new log entry appears."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM history")
            count = cur.fetchone()[0]
            conn.close()

            if count != self.last_count:
                self.load_logs()
        except Exception:
            pass

    def load_logs(self, first=False):
        """Load logs from the database into the list."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT username, action, description, timestamp FROM history ORDER BY id DESC LIMIT 200")
            logs = cur.fetchall()
            conn.close()

            self.log_list.clear()

            if not logs:
                self.log_list.addItem("(No logs yet)")
                return

            for username, action, desc, time in logs:
                formatted = f"[{time}] 👤 {username:<12} | ⚙️ {action:<15} | 📝 {desc}"
                self.log_list.addItem(formatted)

            if first:
                self.last_count = len(logs)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load logs:\n{e}")

    # ==========================================================
    # Clear Logs (Admin only, logs older than 1 minute)
    # ==========================================================
    def clear_old_logs(self):
        """Allow admin to delete only logs older than 1 minute."""
        confirm = QMessageBox.question(self, "Confirm", "Delete logs older than 1 minute?")
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=1)
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()

            # SQLite stores timestamps as text, so we filter properly
            cur.execute("DELETE FROM history WHERE timestamp <= ?", (cutoff_time.strftime("%Y-%m-%d %H:%M:%S"),))
            deleted = cur.rowcount
            conn.commit()
            conn.close()

            if deleted > 0:
                QMessageBox.information(self, "Cleared", f"🧹 {deleted} old log(s) deleted successfully.")
            else:
                QMessageBox.information(self, "Info", "No logs older than 1 minute found.")

            self.load_logs()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to clear old logs:\n{e}")
