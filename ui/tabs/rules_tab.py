import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QHBoxLayout, QMessageBox, QComboBox
)
from PyQt6.QtGui import QFont
from pyrewall.ui.button_styles import make_button
from pyrewall.db.storage import log_general_history
from pyrewall.db.paths import FIREWALL_DB as DB_PATH

class RulesTab(QWidget):
    """UI for managing custom firewall rules (IP, port, and protocol)."""
    def __init__(self, username):
        super().__init__()
        self.username = username

        # --- Layout setup ---
        layout = QVBoxLayout()
        title = QLabel("🛡️ Custom Firewall Rules")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # --- Input Fields ---
        input_layout = QHBoxLayout()

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Target IP address (e.g., 192.168.1.10)")
        input_layout.addWidget(self.ip_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g., 80 or ANY)")
        input_layout.addWidget(self.port_input)

        self.protocol_input = QComboBox()
        self.protocol_input.addItems(["TCP", "UDP", "ICMP", "ANY"])
        input_layout.addWidget(self.protocol_input)

        self.action_input = QComboBox()
        self.action_input.addItems(["BLOCK", "ALLOW"])
        input_layout.addWidget(self.action_input)

        add_btn = make_button("Add Rule", variant="primary", height=28)
        remove_btn = make_button("Remove Rule", variant="danger", height=28)
        refresh_btn = make_button("Refresh", variant="primary", height=28)
        input_layout.addWidget(add_btn)
        input_layout.addWidget(remove_btn)
        input_layout.addWidget(refresh_btn)

        layout.addLayout(input_layout)

        # --- Rules List ---
        self.rules_list = QListWidget()
        layout.addWidget(self.rules_list)
        self.setLayout(layout)

        # --- Initialize Database ---
        self._init_db()

        # --- Connect Buttons ---
        add_btn.clicked.connect(self.add_rule)
        remove_btn.clicked.connect(self.remove_rule)
        refresh_btn.clicked.connect(self.load_rules)

        # --- Initial Load ---
        self.load_rules()

    # ====================================================
    # 🧱 DATABASE OPERATIONS
    # ====================================================

    def _init_db(self):
        """Ensure firewall_rules table exists."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    ip TEXT,
                    port TEXT,
                    protocol TEXT,
                    action TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Pyrewall] Rules DB init error: {e}")

    def _get_all_rules(self):
        """Retrieve all saved rules."""
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT ip, port, protocol, action FROM firewall_rules")
        rules = cur.fetchall()
        conn.close()
        return rules

    def _rule_exists(self, ip, port, protocol, action):
        """Check if the rule already exists to prevent duplicates."""
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM firewall_rules
            WHERE ip = ? AND port = ? AND protocol = ? AND action = ?
        """, (ip, port, protocol, action))
        exists = cur.fetchone()[0] > 0
        conn.close()
        return exists

    # ====================================================
    # ➕ ADD RULE
    # ====================================================

    def add_rule(self):
        """Add a new firewall rule."""
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip() or "ANY"
        protocol = self.protocol_input.currentText()
        action = self.action_input.currentText()

        if not ip:
            QMessageBox.warning(self, "Warning", "Please enter an IP address.")
            return
        if port != "ANY" and not port.isdigit():
            QMessageBox.warning(self, "Warning", "Port must be numeric or 'ANY'.")
            return

        if self._rule_exists(ip, port, protocol, action):
            QMessageBox.warning(self, "Duplicate Rule", "This rule already exists.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO firewall_rules(username, ip, port, protocol, action)
                VALUES (?, ?, ?, ?, ?)
            """, (self.username, ip, port, protocol, action))
            conn.commit()
            conn.close()

            log_general_history(self.username, "Add Rule", f"{action} {protocol} {ip}:{port}")
            self.load_rules()

            QMessageBox.information(self, "Success", f"✅ Rule added: {action} {protocol} {ip}:{port}")
            self.ip_input.clear()
            self.port_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add rule:\n{e}")

    # ====================================================
    # ❌ REMOVE RULE
    # ====================================================

    def remove_rule(self):
        """Remove selected rule."""
        selected_item = self.rules_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Warning", "Please select a rule to remove.")
            return

        rule_text = selected_item.text()
        try:
            parts = rule_text.split()
            action, protocol = parts[0], parts[1]
            ip_port = parts[2] if len(parts) > 2 else ""
            ip, port = (ip_port.split(":") + ["ANY"])[:2]

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                DELETE FROM firewall_rules
                WHERE ip = ? AND port = ? AND protocol = ? AND action = ?
            """, (ip, port, protocol, action))
            conn.commit()
            conn.close()

            log_general_history(self.username, "Remove Rule", f"Removed {action} {protocol} {ip}:{port}")
            self.load_rules()

            QMessageBox.information(self, "Removed", f"❎ Rule removed: {rule_text}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove rule:\n{e}")

    # ====================================================
    # 🔁 REFRESH
    # ====================================================

    def load_rules(self):
        """Load all firewall rules into the list."""
        self.rules_list.clear()
        try:
            rules = self._get_all_rules()
            if not rules:
                self.rules_list.addItem("(No custom rules configured)")
                return

            for ip, port, protocol, action in rules:
                rule_text = f"{action} {protocol} {ip}:{port}"
                self.rules_list.addItem(rule_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load rules:\n{e}")
