from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB, USERS_DB, GENERAL_HISTORY_DB
# pyrewall/ui/devices_tab.py
import os
import csv
import subprocess
import platform
import sqlite3
import ipaddress
import time
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton,
    QHBoxLayout, QMessageBox, QGridLayout
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from pyrewall.db.storage import log_general_history

# NEW IMPORTS
from pyrewall.core.devices import detect_devices, add_blocked_device, remove_blocked_device, get_blocked_devices




# ============================================================
# BACKGROUND THREAD — DEVICE SCANNER
# ============================================================
class DeviceScanner(QThread):
    """Background worker that scans local network and identifies device vendors/types."""
    devices_found = pyqtSignal(list)
    scan_error = pyqtSignal(str)

    # 🧩 Class-level vendor database (shared by all instances)
    vendor_db = {}

    def __init__(self):
        super().__init__()
        # Load the vendor DB once when the first scanner runs
        if not DeviceScanner.vendor_db:
            DeviceScanner.load_vendor_db()

    # ============================================================
    # 📘 Load Local Vendor Database (Offline MAC Prefix Lookup)
    # ============================================================
    @classmethod
    def load_vendor_db(cls):
        """Load OUI → Vendor mapping from a CSV file."""
        vendor_file = os.path.join("pyrewall", "assets", "mac_vendors.csv")

        if not os.path.exists(vendor_file):
            print("[Pyrewall] ⚠️ Vendor file not found — creating minimal fallback.")
            # Minimal fallback in case CSV is missing
            cls.vendor_db = {
                "00:1A:2B": "Apple",
                "00:1B:63": "HP",
                "00:25:9C": "Samsung",
                "F4:5C:89": "Xiaomi",
                "3C:5A:B4": "ASUS",
            }
            return

        try:
            with open(vendor_file, "r", encoding="utf-8") as f:
                for row in csv.reader(f):
                    if len(row) >= 2:
                        oui = row[0].strip().upper()
                        vendor = row[1].strip()
                        if oui and vendor:
                            cls.vendor_db[oui] = vendor
            print(f"[Pyrewall] ✅ Loaded {len(cls.vendor_db)} MAC vendors.")
        except Exception as e:
            print(f"[Pyrewall] ⚠️ Failed to load MAC vendor database: {e}")

    # ============================================================
    # 🔍 Vendor + Type Detection (Dynamic)
    # ============================================================
    def _lookup_vendor_and_type(self, mac):
        """Return vendor and inferred device type based on MAC prefix."""
        prefix = mac.upper().replace("-", ":")[:8]
        vendor = self.vendor_db.get(prefix, "Unknown Vendor")

        # 🧠 Infer device type by known vendor
        if any(x in vendor for x in ["SAMSUNG", "OPPO", "VIVO", "XIAOMI", "HUAWEI"]):
            dev_type = "Android Phone"
        elif any(x in vendor for x in ["APPLE"]):
            dev_type = "iPhone / Mac"
        elif any(x in vendor for x in ["DELL", "HP", "LENOVO", "ASUS", "ACER", "MSI"]):
            dev_type = "Laptop / PC"
        elif "TP-LINK" in vendor or "TCL" in vendor or "REALME" in vendor:
            dev_type = "Router / IoT"
        else:
            dev_type = "Unknown Device"

        return vendor, dev_type

    # ============================================================
    # 🛰️ Main Network Scan
    # ============================================================
    def run(self):
        """Accurate scan using ARP + hostednetwork cross-check."""
        try:
            devices = []

            # 1️⃣ Get currently connected MACs from hostednetwork
            connected_macs = set()
            try:
                output = subprocess.check_output(
                    ["netsh", "wlan", "show", "hostednetwork"],
                    text=True, encoding="utf-8", errors="ignore"
                )
                mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
                connected_macs = {m.group(0).lower().replace("-", ":") for m in mac_pattern.finditer(output)}
            except Exception as e:
                print("[devices] ⚠️ Failed to read hostednetwork clients:", e)

            # 2️⃣ Read ARP table
            output = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore")
            pattern = re.compile(r"(192\.168\.137\.\d+)\s+([0-9A-Fa-f:-]{11,})")

            for ip, mac in pattern.findall(output):
                mac_normalized = mac.lower().replace("-", ":")

                # Skip broadcast, multicast, invalid, or stale entries
                if (
                        ip.endswith(".255")
                        or mac_normalized.startswith("ff:")
                        or mac_normalized.startswith("01:00:5e")
                        or mac_normalized.startswith("33:33")
                ):
                    continue

                # ✅ Only keep MACs currently connected
                if connected_macs and mac_normalized not in connected_macs:
                    continue

                vendor, dev_type = self._lookup_vendor_and_type(mac)
                devices.append((ip, mac, vendor, dev_type))

            devices.sort(key=lambda x: list(map(int, x[0].split("."))))
            self.devices_found.emit(devices)

        except Exception as e:
            self.scan_error.emit(str(e))


# ============================================================
# MAIN DEVICES TAB — AUTO REFRESHING DASHBOARD
# ============================================================
class DevicesTab(QWidget):
    """UI for detecting, blocking, and monitoring network devices."""
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.blocked_devices = set()
        self._init_device_db()
        self.scanning = False  # prevents overlapping scans

        layout = QVBoxLayout()
        title = QLabel("📡 Live Device Management")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # --- Buttons ---
        button_layout = QHBoxLayout()
        self.detect_btn = QPushButton("🔍 Scan Now")
        self.block_btn = QPushButton("⛔ Block Selected")
        self.unblock_btn = QPushButton("✅ Unblock Selected")

        for btn in [self.detect_btn, self.block_btn, self.unblock_btn]:
            btn.setFixedHeight(32)

        self.detect_btn.setStyleSheet("background-color:#007BFF;color:white;border-radius:6px;padding:4px 10px;")
        self.block_btn.setStyleSheet("background-color:#dc3545;color:white;border-radius:6px;padding:4px 10px;")
        self.unblock_btn.setStyleSheet("background-color:#28a745;color:white;border-radius:6px;padding:4px 10px;")

        button_layout.addWidget(self.detect_btn)
        button_layout.addWidget(self.block_btn)
        button_layout.addWidget(self.unblock_btn)
        layout.addLayout(button_layout)

        # --- Dual Device Lists (Grid Layout) ---
        grid = QGridLayout()
        self.active_list = QListWidget()
        self.blocked_list = QListWidget()

        active_label = QLabel("🟢 Active Devices")
        blocked_label = QLabel("🔴 Blocked Devices")
        active_label.setFont(QFont("Helvetica", 11, QFont.Weight.Bold))
        blocked_label.setFont(QFont("Helvetica", 11, QFont.Weight.Bold))

        grid.addWidget(active_label, 0, 0)
        grid.addWidget(blocked_label, 0, 1)
        grid.addWidget(self.active_list, 1, 0)
        grid.addWidget(self.blocked_list, 1, 1)
        layout.addLayout(grid)

        self.setLayout(layout)

        # --- Button Connections ---
        self.detect_btn.clicked.connect(self.detect_devices)
        self.block_btn.clicked.connect(self.block_device)
        self.unblock_btn.clicked.connect(self.unblock_device)

        # --- Auto refresh every 10 seconds ---
        self.timer = QTimer()
        self.timer.timeout.connect(self.detect_devices)
        self.timer.start(12000)

        # --- Initial Load ---
        self.load_blocked_devices()
        self._sync_firewall_with_db()
        self.detect_devices()

    # ============================================================
    # DATABASE HELPERS
    # ============================================================
    def _init_device_db(self):
        """Ensure table for blocked devices exists."""
        conn = sqlite3.connect(DEFAULT_DB)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                date_blocked TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def load_blocked_devices(self):
        """Load blocked devices from DB."""
        self.blocked_list.clear()
        devices = get_blocked_devices()
        if not devices:
            self.blocked_list.addItem("(No blocked devices)")
        else:
            for ip, mac in devices:
                self.blocked_list.addItem(f"{ip} ({mac})")

    def _sync_firewall_with_db(self):
        """Ensure Windows Firewall rules match entries in blocked_devices DB."""
        try:
            conn = sqlite3.connect(DEFAULT_DB)
            cur = conn.cursor()
            cur.execute("SELECT ip FROM blocked_devices")
            blocked = [row[0] for row in cur.fetchall()]
            conn.close()

            for ip in blocked:
                for direction in ["in", "out"]:
                    rule_name = f"Pyrewall_Block_{ip}_{direction}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block", f"remoteip={ip}"
                    ], capture_output=True, text=True)
        except Exception as e:
            print(f"[Devices] Sync firewall error: {e}")

    # ============================================================
    # SCANNING + DISPLAY
    # ============================================================
    def detect_devices(self):
        """Trigger async scan safely (prevents overlapping scans)."""
        if self.scanning:
            return  # already scanning
        self.scanning = True

        self.active_list.clear()
        self.active_list.addItem("🛰️ Scanning network... please wait")
        self.scanner = DeviceScanner()
        self.scanner.devices_found.connect(self.show_devices)
        self.scanner.scan_error.connect(self.show_scan_error)

        # clear scanning flag when finished
        self.scanner.finished.connect(lambda: setattr(self, "scanning", False))

        self.scanner.start()

    def show_devices(self, devices):
        """Update active devices list."""
        self.active_list.clear()

        # build blocked ips set from blocked_list items
        blocked_ips = set()
        for j in range(self.blocked_list.count()):
            item = self.blocked_list.item(j)
            if not item:
                continue
            txt = item.text().strip()
            if not txt or txt.startswith("("):
                continue
            # ip is first token
            blocked_ips.add(txt.split()[0])

        if not devices:
            self.active_list.addItem("(No active devices detected)")
            return

        for ip, mac, vendor, dev_type in devices:
            marker = "❌" if ip in blocked_ips else "✅"
            self.active_list.addItem(f"{marker} {ip} ({mac}) • {vendor} • {dev_type}")

    def show_scan_error(self, error_message):
        self.active_list.clear()
        self.active_list.addItem("Error: " + error_message)

    # ============================================================
    # BLOCK / UNBLOCK
    # ============================================================
    def block_device(self):
        """Block selected device."""
        selected = self.active_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a device to block.")
            return

        ip = selected.text().split()[1]
        try:
            add_blocked_device(ip)
            log_general_history(self.username, "Block Device", f"Blocked {ip}")
            QMessageBox.information(self, "Device Blocked", f"⛔ {ip} has been blocked.")
            self.load_blocked_devices()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block device:\n{e}")

    def unblock_device(self):
        """Unblock selected device."""
        selected = self.blocked_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a device to unblock.")
            return

        text = selected.text().strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+", text):
            QMessageBox.warning(self, "Invalid selection", "Please select a valid device to unblock.")
            return
        ip = text.split()[0]

        try:
            remove_blocked_device(ip)
            log_general_history(self.username, "Unblock Device", f"Unblocked {ip}")
            QMessageBox.information(self, "Device Unblocked", f"✅ {ip} has been unblocked.")
            self.load_blocked_devices()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unblock device:\n{e}")


