# pyrewall/ui/tabs/websites_tab.py
import os
import sqlite3
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QMessageBox, QHBoxLayout
)
from pyrewall.core.firewall_thread import (
    add_blocked_domain, remove_blocked_domain,
    reload_blocked_domains, sync_blocked_ips,
    notify_firewall_reload
)

from pyrewall.db.storage import log_general_history


class WebsitesTab(QWidget):
    def __init__(self, username: str):
        super().__init__()
        self.username = username
        self.db_path = os.path.join(os.path.dirname(__file__), "..", "..", "db", "firewall.db")

        layout = QVBoxLayout()
        title = QLabel("🌐 Website Blocking")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        input_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter website domain (e.g., facebook.com)")
        input_layout.addWidget(self.domain_input)

        add_btn = QPushButton("Add")
        remove_btn = QPushButton("Remove")
        refresh_btn = QPushButton("Refresh")
        for btn in (add_btn, remove_btn, refresh_btn):
            btn.setFixedHeight(32)
            btn.setStyleSheet("""
                QPushButton { background-color: #0078D7; color: white; border-radius: 5px; }
                QPushButton:hover { background-color: #005fa3; }
            """)
        input_layout.addWidget(add_btn)
        input_layout.addWidget(remove_btn)
        input_layout.addWidget(refresh_btn)
        layout.addLayout(input_layout)

        self.domain_list = QListWidget()
        layout.addWidget(self.domain_list)

        self.setLayout(layout)

        add_btn.clicked.connect(self.add_site)
        remove_btn.clicked.connect(self.remove_site)
        refresh_btn.clicked.connect(self.load_blocked_sites)

        self._init_db()
        self.load_blocked_sites()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
            cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips(ip TEXT UNIQUE)")
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Init DB failed:\n{e}")

    def load_blocked_sites(self):
        self.domain_list.clear()
        try:
            domains = reload_blocked_domains(self.db_path)
            if domains:
                for d in domains:
                    self.domain_list.addItem(d)
            else:
                self.domain_list.addItem("⚠️ No blocked domains yet.")
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load blocked sites:\n{e}")

    def add_site(self):
        domain = self.domain_input.text().strip().lower()
        if not domain:
            QMessageBox.warning(self, "Warning", "Please enter a domain.")
            return
        if " " in domain or "." not in domain:
            QMessageBox.warning(self, "Invalid", "Enter a valid domain (example.com).")
            return

        try:
            add_blocked_domain(domain, self.db_path)
            sync_blocked_ips(self.db_path)
            notify_firewall_reload()
            log_general_history(self.username, "Block Website", domain)
            self.domain_input.clear()
            self.load_blocked_sites()
            QMessageBox.information(self, "Success", f"Blocked {domain}.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block site:\n{e}")

    def remove_site(self):
        selected = self.domain_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Select a domain to remove.")
            return
        domain = selected.text().strip().lower()
        if domain.startswith("⚠️"):
            return
        try:
            remove_blocked_domain(domain, self.db_path)
            sync_blocked_ips(self.db_path)
            notify_firewall_reload()
            log_general_history(self.username, "Unblock Website", domain)
            self.load_blocked_sites()
            QMessageBox.information(self, "Success", f"Unblocked {domain}.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unblock site:\n{e}")
