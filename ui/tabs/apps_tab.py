# pyrewall/ui/tabs/apps_tab.py
import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QHBoxLayout, QMessageBox, QComboBox, QFormLayout
)
from PyQt6.QtGui import QFont
from pyrewall.db.storage import log_general_history
from pyrewall.db.app_signatures import add_signature, remove_signature, get_all_signatures, init_app_signatures

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "pyrewall", "db", "firewall.db"))

class AppsTab(QWidget):
    """Network-based Application Blocking (pattern/ip/protocol)"""
    def __init__(self, username):
        super().__init__()
        self.username = username

        layout = QVBoxLayout()
        title = QLabel("🧩 Application Signatures (Network Blocking)")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Form inputs
        form_layout = QFormLayout()
        self.name_input = QLineEdit()
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("Domain pattern, e.g. *.youtube.com or api.spotify.com")
        self.ip_range_input = QLineEdit()
        self.ip_range_input.setPlaceholderText("Optional IP range or CIDR, e.g. 203.0.113.0/24")
        self.protocol_input = QComboBox()
        self.protocol_input.addItems(["ANY", "TCP", "UDP", "HTTP", "HTTPS"])
        form_layout.addRow("App Name:", self.name_input)
        form_layout.addRow("Domain Pattern:", self.pattern_input)
        form_layout.addRow("IP Range:", self.ip_range_input)
        form_layout.addRow("Protocol:", self.protocol_input)
        layout.addLayout(form_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Signature")
        remove_btn = QPushButton("Remove Selected")
        refresh_btn = QPushButton("Refresh")
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)

        # Signature list
        self.sig_list = QListWidget()
        layout.addWidget(self.sig_list)
        self.setLayout(layout)

        # Connections
        add_btn.clicked.connect(self.add_sig)
        remove_btn.clicked.connect(self.remove_sig)
        refresh_btn.clicked.connect(self.load_signatures)

        # Ensure DB table
        init_app_signatures(DB_PATH)
        self.load_signatures()

    def load_signatures(self):
        self.sig_list.clear()
        try:
            rows = get_all_signatures(DB_PATH)
            if not rows:
                self.sig_list.addItem("(No app signatures configured)")
                return
            for r in rows:
                sid, name, pattern, ipr, proto, domain_pattern = r
                proto = proto or "ANY"
                pattern_display = pattern or domain_pattern or ""
                self.sig_list.addItem(f"{sid} | {name} | {pattern_display} | {ipr or ''} | {proto}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load signatures:\n{e}")

    def add_sig(self):
        name = self.name_input.text().strip()
        pattern = self.pattern_input.text().strip() or None
        ipr = self.ip_range_input.text().strip() or None
        proto = self.protocol_input.currentText()
        if not name:
            QMessageBox.warning(self, "Warning", "Please provide an app name.")
            return
        try:
            add_signature(name, pattern=pattern, ip_range=ipr, protocol=proto, db_path=DB_PATH)
            log_general_history(self.username, "Add Signature", f"{name} ({pattern or ''} {ipr or ''} {proto})")
            QMessageBox.information(self, "Added", f"✅ Signature added for: {name}")
            self.name_input.clear(); self.pattern_input.clear(); self.ip_range_input.clear()
            self.load_signatures()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add signature:\n{e}")

    def remove_sig(self):
        item = self.sig_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a signature to remove.")
            return
        text = item.text().split("|")[0].strip()
        try:
            sig_id = int(text)
        except Exception:
            QMessageBox.warning(self, "Invalid", "Selected item cannot be removed.")
            return
        try:
            remove_signature(signature_id=sig_id, db_path=DB_PATH)
            log_general_history(self.username, "Remove Signature", f"id={sig_id}")
            QMessageBox.information(self, "Removed", f"❎ Signature id {sig_id} removed.")
            self.load_signatures()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove signature:\n{e}")
