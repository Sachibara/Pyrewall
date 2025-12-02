# network_control_tab.py
import os
import re
import threading
import time
import sqlite3
import subprocess
import shlex
import csv
from typing import List, Tuple
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QListWidget, QListWidgetItem, QLineEdit,
    QPushButton, QMessageBox, QFormLayout, QComboBox, QGridLayout, QFrame,
    QAbstractItemView, QSizePolicy
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import QTimer, Qt, QThread, pyqtSignal
from pyrewall.ui.button_styles import make_button

# Try to reuse the project's GraphWidget if present; otherwise provide a fallback.
try:
    from pyrewall.ui.components.graph_widget import GraphWidget
except Exception:
    try:
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
        from matplotlib.figure import Figure
        from PyQt6.QtWidgets import QVBoxLayout
    except Exception:
        class GraphWidget(QWidget):
            def __init__(self, title="Traffic Graph"):
                super().__init__()
                lbl = QLabel(title)
                layout = QVBoxLayout(self)
                layout.addWidget(lbl)
            def update_graph(self, data):
                pass
    else:
        class GraphWidget(QWidget):
            def __init__(self, title="Traffic Graph"):
                super().__init__()
                layout = QVBoxLayout(self)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(0)
                self.figure = Figure(figsize=(4, 2))
                self.canvas = FigureCanvas(self.figure)
                layout.addWidget(self.canvas)
                self._title = title
                self._ax = self.figure.add_subplot(111)
                self._ax.set_title(self._title)
                self._ax.grid(True)
                self.canvas.draw()
            def update_graph(self, data):
                try:
                    self.figure.clear()
                    ax = self.figure.add_subplot(111)
                    ax.grid(True)
                    if not data:
                        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=10, color="gray")
                    else:
                        try:
                            x = list(range(len(data)))
                            y = [float(v) for v in data]
                        except Exception:
                            x = list(range(len(data)))
                            y = [0 for _ in data]
                        ax.plot(x, y, label="Traffic")
                        ax.set_xlabel("Samples")
                        ax.set_ylabel("Value")
                        ax.legend(loc="upper right")
                    self.figure.tight_layout()
                    self.canvas.draw_idle()
                except Exception as e:
                    print(f"[GraphWidget] update error: {e}")

# ------------------- SAFE IMPORTS (Defensive) -------------------
try:
    from pyrewall.core.firewall_thread import (
        add_blocked_domain, remove_blocked_domain,
        reload_blocked_domains, sync_blocked_ips,
        notify_firewall_reload
    )
except Exception as e:
    print("[NetworkControl] ⚠️ firewall_thread import failed:", e)
    def add_blocked_domain(domain, db_path=None): raise RuntimeError("firewall_thread missing")
    def remove_blocked_domain(domain, db_path=None): raise RuntimeError("firewall_thread missing")
    def reload_blocked_domains(db_path=None): return []
    def sync_blocked_ips(db_path=None): pass
    def notify_firewall_reload(): pass

# App signatures
try:
    from pyrewall.db.app_signatures import (
        add_signature, remove_signature,
        get_all_signatures, init_app_signatures
    )
except Exception as e:
    print("[NetworkControl] ⚠️ app_signatures import failed:", e)
    def add_signature(*a, **k): raise RuntimeError("app_signatures missing")
    def remove_signature(*a, **k): raise RuntimeError("app_signatures missing")
    def get_all_signatures(*a, **k): return []
    def init_app_signatures(*a, **k): pass

# Devices
try:
    from pyrewall.core.devices import (
        detect_devices, add_blocked_device,
        remove_blocked_device, get_blocked_devices
    )
except Exception as e:
    print("[NetworkControl] ⚠️ devices import failed:", e)
    def detect_devices(): return []
    def add_blocked_device(ip): raise RuntimeError("devices missing")
    def remove_blocked_device(ip): raise RuntimeError("devices missing")
    def get_blocked_devices(): return []

# Logging
from pyrewall.db.storage import log_general_history
from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB

# Use the exact same DB path as the firewall thread
DB_PATH = DEFAULT_DB

def _normalize_domain(raw: str) -> str | None:
    """
    Take user input like:
      - https://www.youtube.com/watch?v=123
      - www.facebook.com/
      - facebook.com:443
    and normalize to a clean domain:
      -> youtube.com or www.youtube.com
      -> facebook.com
    Returns None if invalid.
    """
    if not raw:
        return None
    s = raw.strip().lower()

    # Strip scheme
    if s.startswith("http://") or s.startswith("https://"):
        s = s.split("://", 1)[1]

    # Strip path, query, fragment
    for sep in ["/", "?", "#"]:
        if sep in s:
            s = s.split(sep, 1)[0]

    # Strip port if present
    if ":" in s:
        s = s.split(":", 1)[0]

    # Strip leading/trailing dots and spaces
    s = s.strip().strip(".")

    # Basic sanity
    if not s or " " in s or "." not in s:
        return None

    return s


def db_retry(fn, retries=5, delay=0.15):
    for _ in range(retries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                time.sleep(delay)
                continue
            raise
    raise RuntimeError("DB remained locked after retries")

# ============================================================
# BACKGROUND THREAD — DEVICE SCANNER (from old DevicesTab)
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
        v_upper = vendor.upper()
        if any(x in v_upper for x in ["SAMSUNG", "OPPO", "VIVO", "XIAOMI", "HUAWEI"]):
            dev_type = "Android Phone"
        elif "APPLE" in v_upper:
            dev_type = "iPhone / Mac"
        elif any(x in v_upper for x in ["DELL", "HP", "LENOVO", "ASUS", "ACER", "MSI"]):
            dev_type = "Laptop / PC"
        elif "TP-LINK" in v_upper or "TCL" in v_upper or "REALME" in v_upper:
            dev_type = "Router / IoT"
        else:
            dev_type = "Unknown Device"

        return vendor, dev_type

    # ============================================================
    # 🧪 Small helper: check if an IP is really alive (Windows ping)
    # ============================================================
    def _ping_ip(self, ip, timeout_ms: int = 400) -> bool:
        """
        Return True if the host responds to a single ping within timeout_ms.
        Windows syntax:
          ping -n 1 -w <timeout_ms> <ip>
        """
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"[devices] ping failed for {ip}: {e}")
            return False

    # ============================================================
    # 🛰️ Main Network Scan (ARP only + ping, 1 row per real device)
    # ============================================================
    def run(self):
        """
        Scan 192.168.137.x using the ARP table.

        1. Read 'arp -a' and collect all entries in 192.168.137.x
        2. Group IPs by MAC address
        3. Ping each IP; keep only ones that respond (drop stale ARP entries)
        4. For each MAC, pick a single alive IP (lowest) so we get exactly
           one row per physical device.
        """
        try:
            # 1) Grab ARP table
            try:
                output = subprocess.check_output(
                    ["arp", "-a"], text=True, encoding="utf-8", errors="ignore"
                )
            except Exception as e:
                print("[devices] ⚠️ arp -a failed:", e)
                self.devices_found.emit([])
                return

            # 2) Group IPs by MAC for 192.168.137.x
            ip_by_mac = {}
            pattern = re.compile(r"(192\.168\.137\.\d+)\s+([0-9A-Fa-f:-]{11,})")

            for ip, mac in pattern.findall(output):
                mac_normalized = mac.lower().replace("-", ":")

                # Skip the ICS gateway / host laptop itself
                if ip == "192.168.137.1":
                    continue

                # Skip broadcast/multicast/obvious junk
                if (
                        ip.endswith(".255")
                        or mac_normalized.startswith("ff:")
                        or mac_normalized.startswith("01:00:5e")
                        or mac_normalized.startswith("33:33")
                ):
                    continue

                ip_by_mac.setdefault(mac_normalized, set()).add(ip)

            # 3) For each MAC, keep only IPs that respond to ping
            devices = []
            for mac_norm, ips in ip_by_mac.items():
                if not ips:
                    continue

                alive_ips = []
                for ip in sorted(ips, key=lambda s: list(map(int, s.split(".")))):
                    if self._ping_ip(ip):
                        alive_ips.append(ip)

                # If none of the IPs respond, treat this MAC as offline
                if not alive_ips:
                    continue

                # Pick the first alive IP (lowest address)
                ip = alive_ips[0]
                vendor, dev_type = self._lookup_vendor_and_type(mac_norm)
                devices.append((ip, mac_norm.upper(), vendor, dev_type))

            # 4) Sort and send to UI
            devices.sort(key=lambda x: list(map(int, x[0].split("."))))
            self.devices_found.emit(devices)

        except Exception as e:
            self.scan_error.emit(str(e))


class NetworkControlTab(QWidget):
    """
    Dashboard with 4 quadrants:
      TL: Website Blocking
      TR: Traffic Graph (aligned to TL)
      BL: Device detection & blocking
      BR: Application signatures / blocking (height aligned with BL)
    """
    def __init__(self, username: str):
        super().__init__()
        self.username = username

        # Top-level layout: vertical with top-row and bottom-row
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(12)

        # Styling for boxes (frames)
        self._panel_style = """
        QFrame.dashboard-panel {
            background: #ffffff;
            border: 1px solid rgba(16,19,23,0.07);
            border-radius: 6px;
        }
        """

        # ---------- Build each quadrant as its own QFrame w/ internal layout ----------
        # ---------------- Top Row (Website | Graph) ----------------
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        # Top-left: Website Blocking frame
        w_frame = QFrame()
        w_frame.setObjectName("websitePanel")
        w_frame.setProperty("class", "dashboard-panel")
        w_frame.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        w_layout = QVBoxLayout()
        w_layout.setContentsMargins(12, 12, 12, 12)
        w_layout.setSpacing(8)

        w_title = QLabel("🌐 Website Blocking")
        w_title.setFont(QFont("Helvetica", 13, QFont.Weight.Bold))
        w_layout.addWidget(w_title)

        w_form = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.setFixedHeight(28)
        self.add_site_btn = make_button("Add", variant="primary", height=28, width=84)
        self.rm_site_btn = make_button("Remove", variant="danger", height=28, width=84)
        self.refresh_site_btn = make_button("Refresh", variant="primary", height=28, width=84)
        w_form.addWidget(self.domain_input)
        w_form.addWidget(self.add_site_btn)
        w_form.addWidget(self.rm_site_btn)
        w_form.addWidget(self.refresh_site_btn)
        w_layout.addLayout(w_form)

        w_sel_row = QHBoxLayout()
        self.select_all_btn = make_button("Select All", variant="ghost", height=26)
        w_sel_row.addWidget(self.select_all_btn)
        w_sel_row.addStretch()
        w_layout.addLayout(w_sel_row)

        self.domain_list = QListWidget()
        self.domain_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        w_layout.addWidget(self.domain_list)
        w_frame.setLayout(w_layout)

        # Top-right: Graph frame (aligned height to website)
        g_frame = QFrame()
        g_frame.setObjectName("graphPanel")
        g_frame.setProperty("class", "dashboard-panel")
        g_layout = QVBoxLayout()
        g_layout.setContentsMargins(12, 12, 12, 12)
        g_layout.setSpacing(8)

        g_title = QLabel("📈 Traffic")
        g_title.setFont(QFont("Helvetica", 13, QFont.Weight.Bold))
        g_layout.addWidget(g_title)

        try:
            self.graph = GraphWidget("Traffic (last 30 points)")
            self.graph.setMinimumHeight(160)
            self.graph.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            g_layout.addWidget(self.graph)
            try:
                self.graph.update_graph([0, 0, 0])
            except Exception:
                pass
        except Exception as e:
            g_layout.addWidget(QLabel("Graph unavailable: " + str(e)))

        g_frame.setLayout(g_layout)

        # Add top row frames with equal stretch so sizes align
        top_row.addWidget(w_frame, stretch=1)
        top_row.addWidget(g_frame, stretch=1)

        # Force same min height so they align
        min_top_height = 220
        w_frame.setMinimumHeight(min_top_height)
        g_frame.setMinimumHeight(min_top_height)

        outer.addLayout(top_row)

        # ---------------- Bottom Row (Devices | Applications) ----------------
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(12)

        # Bottom-left: Devices frame
        d_frame = QFrame()
        d_frame.setObjectName("devicesPanel")
        d_frame.setProperty("class", "dashboard-panel")
        d_layout = QVBoxLayout()
        d_layout.setContentsMargins(12, 12, 12, 12)
        d_layout.setSpacing(8)

        d_title = QLabel("📡 Devices (Network)")
        d_title.setFont(QFont("Helvetica", 13, QFont.Weight.Bold))
        d_layout.addWidget(d_title)

        dev_btn_row = QHBoxLayout()
        self.scan_btn = make_button("🔍 Scan Now", variant="primary", height=28)
        self.block_dev_btn = make_button("⛔ Block Selected", variant="danger", height=28)
        self.unblock_dev_btn = make_button("✅ Unblock Selected", variant="success", height=28)
        dev_btn_row.addWidget(self.scan_btn)
        dev_btn_row.addWidget(self.block_dev_btn)
        dev_btn_row.addWidget(self.unblock_dev_btn)
        dev_btn_row.addStretch()
        d_layout.addLayout(dev_btn_row)

        grid = QGridLayout()
        active_label = QLabel("🟢 Active Devices")
        blocked_label = QLabel("🔴 Blocked Devices")
        active_label.setFont(QFont("Helvetica", 11, QFont.Weight.Bold))
        blocked_label.setFont(QFont("Helvetica", 11, QFont.Weight.Bold))
        self.active_list = QListWidget()
        self.blocked_list = QListWidget()
        grid.addWidget(active_label, 0, 0)
        grid.addWidget(blocked_label, 0, 1)
        grid.addWidget(self.active_list, 1, 0)
        grid.addWidget(self.blocked_list, 1, 1)
        d_layout.addLayout(grid)

        d_frame.setLayout(d_layout)

        # Bottom-right: Application Signatures frame
        a_frame = QFrame()
        a_frame.setObjectName("appsPanel")
        a_frame.setProperty("class", "dashboard-panel")
        a_layout = QVBoxLayout()
        a_layout.setContentsMargins(12, 12, 12, 12)
        a_layout.setSpacing(8)

        a_title = QLabel("🧩 Application Signatures")
        a_title.setFont(QFont("Helvetica", 13, QFont.Weight.Bold))
        a_layout.addWidget(a_title)

        form_layout = QFormLayout()
        self.app_name_input = QLineEdit()
        self.app_pattern_input = QLineEdit()
        self.app_pattern_input.setPlaceholderText("e.g. *.youtube.com")
        self.ip_range_input = QLineEdit()
        self.protocol_select = QComboBox()
        self.protocol_select.addItems(["ANY", "TCP", "UDP", "HTTP", "HTTPS"])
        form_layout.addRow("Name:", self.app_name_input)
        form_layout.addRow("Pattern:", self.app_pattern_input)
        form_layout.addRow("IP Range:", self.ip_range_input)
        form_layout.addRow("Protocol:", self.protocol_select)
        a_layout.addLayout(form_layout)

        apps_btn_row = QHBoxLayout()
        self.add_sig_btn = make_button("Add Signature", variant="primary", height=28)
        self.rm_sig_btn = make_button("Remove Selected", variant="danger", height=28)
        self.refresh_sig_btn = make_button("Refresh", variant="primary", height=28)
        apps_btn_row.addWidget(self.add_sig_btn)
        apps_btn_row.addWidget(self.rm_sig_btn)
        apps_btn_row.addWidget(self.refresh_sig_btn)
        apps_btn_row.addStretch()
        a_layout.addLayout(apps_btn_row)

        self.sigs_list = QListWidget()
        a_layout.addWidget(self.sigs_list)

        a_frame.setLayout(a_layout)

        # Add bottom row frames with stretch (devices and apps heights aligned)
        bottom_row.addWidget(d_frame, stretch=1)
        bottom_row.addWidget(a_frame, stretch=1)

        # Force same min height for bottom row quadrants
        min_bottom_height = 260
        d_frame.setMinimumHeight(min_bottom_height)
        a_frame.setMinimumHeight(min_bottom_height)

        outer.addLayout(bottom_row)

        # Apply stylesheet to frames (division lines look like your example)
        self.setStyleSheet(self._panel_style)

        # ---------------- Connect signals ----------------
        self.add_site_btn.clicked.connect(self.add_site)
        self.rm_site_btn.clicked.connect(self.remove_site)
        self.refresh_site_btn.clicked.connect(self.load_blocked_sites)
        self.select_all_btn.clicked.connect(self.select_all_sites)

        self.add_sig_btn.clicked.connect(self.add_signature)
        self.rm_sig_btn.clicked.connect(self.remove_signature)
        self.refresh_sig_btn.clicked.connect(self.load_signatures)

        self.scan_btn.clicked.connect(self.scan_devices)
        self.block_dev_btn.clicked.connect(self.block_device)
        self.unblock_dev_btn.clicked.connect(self.unblock_device)

        # prevent overlapping scans
        self._device_scanning = False

        # autos
        self.device_timer = QTimer()
        self.device_timer.timeout.connect(self.scan_devices)
        self.device_timer.start(3000)  # 3s refresh

        # Ensure DB objects
        try:
            init_app_signatures(DB_PATH)
        except Exception:
            pass

        # initial loads
        self.load_blocked_sites()
        self.load_signatures()
        self.load_blocked_devices()
        # initial scan (non-blocking)
        self.scan_devices()

    # ------------------ WEBSITES ------------------
    def load_blocked_sites(self):
        self.domain_list.clear()
        try:
            domains = reload_blocked_domains(self.db_path() if hasattr(self, "db_path") else DB_PATH)
            if not domains:
                self.domain_list.addItem("⚠️ No blocked domains yet.")
            else:
                for d in domains:
                    item = QListWidgetItem(d)
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Unchecked)
                    self.domain_list.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load blocked sites:\n{e}")

    def add_site(self):
        raw = self.domain_input.text()
        domain = _normalize_domain(raw)

        if not domain:
            QMessageBox.warning(
                self,
                "Invalid",
                "Enter a valid domain like example.com (no spaces, no full URL)."
            )
            return

        # Check duplicates in the list (compare normalized)
        for i in range(self.domain_list.count()):
            it = self.domain_list.item(i)
            if not it:
                continue
            existing = _normalize_domain(it.text())
            if existing and existing == domain:
                QMessageBox.information(self, "Info", f"{domain} is already listed.")
                self.domain_input.clear()
                return

        self.add_site_btn.setEnabled(False)
        self.rm_site_btn.setEnabled(False)
        try:
            add_blocked_domain(domain, DB_PATH)

            # ✅ FORCE IMMEDIATE RELOAD FOR FIREWALL + DNS
            try:
                notify_firewall_reload()
            except Exception as e:
                print(f"[NetworkControl] notify_firewall_reload() failed: {e}")

            try:
                log_general_history(self.username, "Block Website", domain)
            except Exception:
                pass
            try:
                if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                    from PyQt6.QtCore import QTimer
                    QTimer.singleShot(
                        0,
                        lambda: self.home.notify_overview_update()
                        if hasattr(self.home, "notify_overview_update")
                        else None
                    )
            except Exception:
                pass

            QMessageBox.information(self, "Added", f"✅ {domain} added to blocked sites.")
            self.domain_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add domain:\n{e}")
        finally:
            try:
                self.load_blocked_sites()
            except Exception:
                pass
            self.add_site_btn.setEnabled(True)
            self.rm_site_btn.setEnabled(True)

    def remove_site(self):
        checked_domains = []
        for i in range(self.domain_list.count()):
            it = self.domain_list.item(i)
            if not it:
                continue
            txt = it.text().strip()
            if not txt or txt.startswith("⚠️") or txt.startswith("("):
                continue
            try:
                if it.checkState() == Qt.CheckState.Checked:
                    checked_domains.append(txt.lower())
            except Exception:
                continue
        if not checked_domains:
            QMessageBox.warning(self, "Select", "Check one or more domains to remove (or use Select All).")
            return
        preview = ", ".join(checked_domains[:6])
        more = f" and {len(checked_domains) - 6} more" if len(checked_domains) > 6 else ""
        reply = QMessageBox.question(self, "Confirm", f"Remove {len(checked_domains)} checked domains?\n{preview}{more}")
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.rm_site_btn.setEnabled(False)
        self.add_site_btn.setEnabled(False)
        self.select_all_btn.setEnabled(False)
        self.refresh_site_btn.setEnabled(False)
        failures = []
        successes = []
        for domain in checked_domains:
            try:
                remove_blocked_domain(domain, DB_PATH)
                try:
                    log_general_history(self.username, "Unblock Website", domain)
                except Exception:
                    pass
                successes.append(domain)
            except Exception as e:
                failures.append((domain, str(e)))
        try:
            sync_blocked_ips(DB_PATH)
        except Exception:
            pass
        try:
            notify_firewall_reload()
        except Exception:
            pass
        try:
            self.load_blocked_sites()
        except Exception:
            pass
        try:
            if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(0, lambda: self.home.notify_overview_update() if hasattr(self.home, "notify_overview_update") else None)
        except Exception:
            pass
        self.rm_site_btn.setEnabled(True)
        self.add_site_btn.setEnabled(True)
        self.select_all_btn.setEnabled(True)
        self.refresh_site_btn.setEnabled(True)
        if failures:
            failed_list = "\n".join(f"{d}: {err}" for d, err in failures[:10])
            more_fail = f"\n...and {len(failures) - 10} more failures" if len(failures) > 10 else ""
            QMessageBox.warning(self, "Partial Failure", f"Removed {len(successes)} domains, but {len(failures)} failed:\n{failed_list}{more_fail}")
        else:
            QMessageBox.information(self, "Removed", f"✅ Removed {len(successes)} domains.")

    def select_all_sites(self):
        try:
            any_unchecked = False
            for i in range(self.domain_list.count()):
                it = self.domain_list.item(i)
                if not it:
                    continue
                txt = it.text().strip()
                if not txt or txt.startswith("⚠️") or txt.startswith("("):
                    continue
                try:
                    if it.checkState() != Qt.CheckState.Checked:
                        any_unchecked = True
                        break
                except Exception:
                    continue
            target = Qt.CheckState.Checked if any_unchecked else Qt.CheckState.Unchecked
            for i in range(self.domain_list.count()):
                it = self.domain_list.item(i)
                if not it:
                    continue
                txt = it.text().strip()
                if not txt or txt.startswith("⚠️") or txt.startswith("("):
                    continue
                try:
                    it.setCheckState(target)
                except Exception:
                    pass
        except Exception as e:
            print(f"[NetworkControl] select_all_sites error: {e}")

    def clear_selection(self):
        try:
            for i in range(self.domain_list.count()):
                it = self.domain_list.item(i)
                if not it:
                    continue
                txt = it.text().strip()
                if not txt or txt.startswith("⚠️") or txt.startswith("("):
                    continue
                try:
                    it.setCheckState(Qt.CheckState.Unchecked)
                except Exception:
                    pass
        except Exception as e:
            print(f"[NetworkControl] clear_selection error: {e}")

    # ------------------ APPLICATION SIGNATURES ------------------
    def load_signatures(self):
        self.sigs_list.clear()
        try:
            rows = get_all_signatures(DB_PATH)
            if not rows:
                self.sigs_list.addItem("(No app signatures configured)")
                return
            for r in rows:
                sid, name, pattern, ipr, proto, domain_pattern = r
                proto = proto or "ANY"
                pattern_display = pattern or domain_pattern or ""
                self.sigs_list.addItem(f"{sid} | {name} | {pattern_display} | {ipr or ''} | {proto}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load signatures:\n{e}")

    def add_signature(self):
        name = self.app_name_input.text().strip()
        pattern = self.app_pattern_input.text().strip() or None
        ipr = self.ip_range_input.text().strip() or None
        proto = self.protocol_select.currentText()
        if not name:
            QMessageBox.warning(self, "Warning", "Please provide an app name.")
            return
        self.add_sig_btn.setEnabled(False)
        def _bg():
            success = False
            err = None
            try:
                add_signature(name, pattern=pattern, ip_range=ipr, protocol=proto, db_path=DB_PATH)
                try:
                    log_general_history(self.username, "Add Signature", f"{name} ({pattern or ''} {ipr or ''} {proto})")
                except Exception:
                    pass
                success = True
            except Exception as e:
                err = e
            finally:
                def _done():
                    self.add_sig_btn.setEnabled(True)
                    if success:
                        QMessageBox.information(self, "Added", f"✅ Signature added for: {name}")
                        self.app_name_input.clear()
                        self.app_pattern_input.clear()
                        self.ip_range_input.clear()
                        self.load_signatures()
                        try:
                            if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                                from PyQt6.QtCore import QTimer
                                QTimer.singleShot(0, lambda: self.home.notify_overview_update() if hasattr(self.home, "notify_overview_update") else None)
                        except Exception:
                            pass
                QTimer.singleShot(1, _done)
        threading.Thread(target=_bg, daemon=True).start()

    def remove_signature(self):
        item = self.sigs_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a signature to remove.")
            return
        text = item.text().split("|")[0].strip()
        try:
            sig_id = int(text)
        except Exception:
            QMessageBox.warning(self, "Invalid", "Selected item cannot be removed.")
            return
        self.rm_sig_btn.setEnabled(False)
        def _bg():
            success = False
            err = None
            try:
                remove_signature(signature_id=sig_id, db_path=DB_PATH)
                try:
                    log_general_history(self.username, "Remove Signature", f"id={sig_id}")
                except Exception:
                    pass
                success = True
            except Exception as e:
                err = e
            finally:
                def _done():
                    self.rm_sig_btn.setEnabled(True)
                    if success:
                        QMessageBox.information(self, "Removed", f"❎ Signature id {sig_id} removed.")
                        self.load_signatures()
                        try:
                            if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                                from PyQt6.QtCore import QTimer
                                QTimer.singleShot(0, lambda: self.home.notify_overview_update() if hasattr(self.home, "notify_overview_update") else None)
                        except Exception:
                            pass
                QTimer.singleShot(1, _done)
        threading.Thread(target=_bg, daemon=True).start()

    # ------------------ DEVICES ------------------
    def db_path(self):
        return DB_PATH

    def load_blocked_devices(self):
        self.blocked_list.clear()
        try:
            devices = get_blocked_devices()
            if not devices:
                self.blocked_list.addItem("(No blocked devices)")
            else:
                for ip, mac in devices:
                    self.blocked_list.addItem(f"{ip} ({mac})")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load blocked devices:\n{e}")

    def scan_devices(self):
        """Trigger async device scan using DeviceScanner (hotspot-focused)."""
        if self._device_scanning:
            return  # already scanning, avoid overlap

        self._device_scanning = True

        # Optional: reflect scanning state on the button, not the list
        try:
            self.scan_btn.setText("🔍 Scanning...")
            self.scan_btn.setEnabled(False)
        except Exception:
            pass

        # Create and wire the QThread-based scanner
        self.scanner = DeviceScanner()
        self.scanner.devices_found.connect(self._on_scan_finished)
        self.scanner.scan_error.connect(self._on_scan_error)

        def _done():
            self._device_scanning = False
            try:
                self.scan_btn.setText("🔍 Scan Now")
                self.scan_btn.setEnabled(True)
            except Exception:
                pass

        self.scanner.finished.connect(_done)

        self.scanner.start()

    def _on_scan_finished(self, devices):
        self.active_list.clear()
        blocked_ips = set()
        devices_for_db = []

        # Collect currently blocked IPs
        for i in range(self.blocked_list.count()):
            it = self.blocked_list.item(i)
            if not it:
                continue
            txt = it.text().strip()
            if not txt or txt.startswith("("):
                continue
            blocked_ips.add(txt.split()[0])

        # If scanner reported an error-ish condition
        if devices is None:
            self.active_list.addItem("Error scanning devices: unknown error")
            try:
                # Clear live_devices so Overview shows 0
                self._update_live_devices_db([])
                if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                    from PyQt6.QtCore import QTimer as _QTimerAlias
                    _QTimerAlias.singleShot(
                        0,
                        lambda: self.home.notify_overview_update()
                        if hasattr(self.home, "notify_overview_update")
                        else None
                    )
            except Exception as e:
                print(f"[NetworkControl] post-scan overview update error (None devices): {e}")
            return

        # No devices at all → show empty + write 0 to DB
        if not devices:
            self.active_list.addItem("(No active devices detected)")
            try:
                self._update_live_devices_db([])
                if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                    from PyQt6.QtCore import QTimer as _QTimerAlias
                    _QTimerAlias.singleShot(
                        0,
                        lambda: self.home.notify_overview_update()
                        if hasattr(self.home, "notify_overview_update")
                        else None
                    )
            except Exception as e:
                print(f"[NetworkControl] post-scan overview update error (empty list): {e}")
            return

        # Normal case: we have a list of device entries
        for entry in devices:
            ip = mac = vendor = dev_type = None
            try:
                if isinstance(entry, dict):
                    ip = entry.get("ip") or entry.get("address") or entry.get("host")
                    mac = entry.get("mac")
                    vendor = entry.get("vendor") or entry.get("vendor_name")
                    dev_type = entry.get("type") or entry.get("dev_type") or entry.get("device_type")
                elif isinstance(entry, (list, tuple)):
                    if len(entry) >= 4:
                        ip, mac, vendor, dev_type = entry[:4]
                    elif len(entry) == 3:
                        ip, mac, vendor = entry
                        dev_type = ""
                    elif len(entry) == 2:
                        ip, mac = entry
                        vendor = ""
                        dev_type = ""
                    else:
                        print(f"[NetworkControl] Skipping malformed scan item (too short): {entry!r}")
                        continue
                else:
                    print(f"[NetworkControl] Skipping unexpected scan item type: {type(entry)} -> {entry!r}")
                    continue

                if not ip or not mac:
                    print(f"[NetworkControl] Skipping incomplete scan entry: {entry!r}")
                    continue

                ip = str(ip).strip()
                mac = str(mac).strip()
                vendor = (vendor or "").strip()
                dev_type = (dev_type or "").strip()

                marker = "❌" if ip in blocked_ips else "✅"
                display = f"{marker} {ip} ({mac})"
                if vendor:
                    display += f" • {vendor}"
                if dev_type:
                    display += f" • {dev_type}"

                self.active_list.addItem(display)

                # For DB snapshot / OverviewTab
                devices_for_db.append((ip, mac, vendor, dev_type))

            except Exception as e:
                print(f"[NetworkControl] Error formatting scan entry {entry!r}: {e}")
                continue

        # --- Update live_devices table + notify overview (if wired) ---
        try:
            self._update_live_devices_db(devices_for_db)
            if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                from PyQt6.QtCore import QTimer as _QTimerAlias
                _QTimerAlias.singleShot(
                    0,
                    lambda: self.home.notify_overview_update()
                    if hasattr(self.home, "notify_overview_update")
                    else None
                )
        except Exception as e:
            print(f"[NetworkControl] post-scan overview update error: {e}")

    def _update_live_devices_db(self, devices_for_db):
        """
        Store the current scan result into firewall.db → live_devices table.

        devices_for_db: list of (ip, mac, vendor, dev_type)
        """
        try:
            db_path = os.path.abspath(DB_PATH)
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            with sqlite3.connect(db_path) as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS live_devices (
                        ip TEXT PRIMARY KEY,
                        mac TEXT,
                        vendor TEXT,
                        dev_type TEXT,
                        last_seen TEXT
                    )
                    """
                )
                # Clear previous snapshot
                cur.execute("DELETE FROM live_devices")
                # Insert fresh snapshot
                from datetime import datetime
                now = datetime.now().isoformat(timespec="seconds")
                for ip, mac, vendor, dev_type in devices_for_db:
                    cur.execute(
                        "INSERT OR REPLACE INTO live_devices (ip, mac, vendor, dev_type, last_seen) VALUES (?, ?, ?, ?, ?)",
                        (ip, mac, vendor, dev_type, now),
                    )
                conn.commit()
        except Exception as e:
            print(f"[NetworkControl] live_devices DB update error: {e}")


    def _on_scan_error(self, msg):
        self.active_list.clear()
        self.active_list.addItem("Error scanning devices: " + msg)

    def block_device(self):
        item = self.active_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a device to block.")
            return
        try:
            txt = item.text().strip()
            ip = txt.split()[1]
        except Exception:
            QMessageBox.warning(self, "Invalid", "Cannot parse selected device.")
            return
        try:
            add_blocked_device(ip)
            log_general_history(self.username, "Block Device", ip)
            QMessageBox.information(self, "Blocked", f"⛔ {ip} blocked.")
            try:
                if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                    from PyQt6.QtCore import QTimer
                    QTimer.singleShot(0, lambda: self.home.notify_overview_update() if hasattr(self.home, "notify_overview_update") else None)
            except Exception:
                pass
            self.load_blocked_devices()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block device:\n{e}")

    def unblock_device(self):
        item = self.blocked_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a blocked device.")
            return
        text = item.text().strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+", text):
            QMessageBox.warning(self, "Invalid", "Select a valid blocked device.")
            return
        ip = text.split()[0]
        try:
            remove_blocked_device(ip)
            log_general_history(self.username, "Unblock Device", ip)
            QMessageBox.information(self, "Unblocked", f"✅ {ip} unblocked.")
            try:
                if hasattr(self, "home") and hasattr(self.home, "notify_overview_update"):
                    from PyQt6.QtCore import QTimer
                    QTimer.singleShot(0, lambda: self.home.notify_overview_update() if hasattr(self.home, "notify_overview_update") else None)
            except Exception:
                pass
            self.load_blocked_devices()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unblock device:\n{e}")
