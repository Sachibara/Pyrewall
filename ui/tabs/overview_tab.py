# pyrewall/ui/tabs/overview_tab.py
import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QGridLayout, QFrame, QHBoxLayout,
    QPushButton, QSizePolicy, QScrollArea, QHeaderView, QTableWidget, QTableWidgetItem
)
from PyQt6.QtGui import QFont, QCursor
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from pyrewall.ui.button_styles import make_button

from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB, USERS_DB, GENERAL_HISTORY_DB

try:
    from pyrewall.ui.components.table_widget import TableWidget
except Exception:
    # fallback simple table widget
    class TableWidget(QTableWidget):
        def __init__(self, headers):
            super().__init__(0, len(headers))
            self.setHorizontalHeaderLabels(headers)

        def load_data(self, rows):
            self.setRowCount(len(rows))
            for r, row_data in enumerate(rows):
                for c, val in enumerate(row_data or []):
                    self.setItem(r, c, QTableWidgetItem(str(val)))

# CSS-like local style
_OVERVIEW_STYLE = """
QWidget {
    background: transparent;
    color: #101317;
    font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 10pt;
}
QFrame#card {
    background: #ffffff;
    border-radius: 10px;
    padding: 12px;
    border: 1px solid rgba(16,19,23,0.06);
    min-height: 110px;
}
QLabel#big {
    font-size: 20pt;
    font-weight: 700;
    color: #0b2f6b;
}
QLabel#small {
    font-size: 10pt;
    color: #53626a;
}
QLabel#title {
    font-size: 13pt;
    font-weight: 700;
    color: #0f1724;
}
QPushButton#refresh {
    min-height: 30px;
    border-radius: 8px;
    padding: 6px 10px;
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0b57d0, stop:1 #0849b8);
    color: white;
    border: none;
}
"""

class ClickableFrame(QFrame):
    clicked = pyqtSignal()
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
    def mouseReleaseEvent(self, ev):
        try:
            if ev.button() == Qt.MouseButton.LeftButton:
                self.clicked.emit()
        except Exception:
            pass
        finally:
            super().mouseReleaseEvent(ev)

class OverviewTab(QWidget):
    card_clicked = pyqtSignal(str)

    def __init__(self, username: str):
        super().__init__()
        self.username = username
        self.setStyleSheet(_OVERVIEW_STYLE)

        # content widget inside scroll area
        content_widget = QWidget()
        outer = QVBoxLayout(content_widget)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(16)

        # Header (title + refresh backup)
        header_row = QHBoxLayout()
        title = QLabel("📊 System Overview")
        title.setObjectName("title")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.DemiBold))
        header_row.addWidget(title)
        header_row.addStretch()

        self.refresh_btn = make_button("Refresh", variant="primary", height=30, object_name="refresh")
        self.refresh_btn.clicked.connect(self.refresh_summary)
        header_row.addWidget(self.refresh_btn)

        outer.addLayout(header_row)

        # GRID for cards and table. We'll rearrange positions per user request.
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)
        grid.setContentsMargins(0, 0, 0, 0)

        # cards
        self.sites_card = self._make_card("🌐 Blocked Websites", "0")
        self.rules_card = self._make_card("🛡️ Firewall Rules", "0")
        self.devices_card = self._make_card("📡 Detected Devices", "Live", small=True)
        self.users_card = self._make_card("👥 Registered Users", "0")
        self.sigs_card = self._make_card("🧩 App Signatures", "0")
        self.threats_card = self._make_card("⚠️ Threats (logs)", "0")

        # uniform sizing: allow cards to expand vertically and avoid forcing widths
        card_min_h = 110
        # remove maximum height and allow vertical expansion so cards can match table height
        for c in (self.sites_card, self.rules_card, self.devices_card,
                  self.users_card, self.sigs_card, self.threats_card):
            c.setMinimumHeight(card_min_h)
            # remove setMaximumHeight to allow growth
            # allow both horizontal and vertical expansion so grid can balance columns
            c.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # --- TABLE INSIDE CARD (matches other cards visually) --------------------
        headers = ["Time", "Event", "Details"]

        # create the actual table instance (kept as self.table so refresh_summary works)
        self.table = TableWidget(headers)

        # configure table behaviour & look
        try:
            self.table.verticalHeader().setVisible(False)
            self.table.setAlternatingRowColors(True)
            self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(self.table.SelectionMode.SingleSelection)
            self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.horizontalHeader().setStretchLastSection(True)
        except Exception:
            pass

        # fonts & sizing so it blends with the cards
        self.table.setFont(QFont("Segoe UI", 9))
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setMinimumHeight(card_min_h * 2 + grid.verticalSpacing())  # height only, not width

        # create a QFrame 'card' for the table so it shares the same chrome/padding
        self.table_card = QFrame()
        self.table_card.setObjectName("card")
        table_card_layout = QVBoxLayout()
        table_card_layout.setContentsMargins(10, 10, 10, 10)
        table_card_layout.setSpacing(6)

        # card title (consistent with other cards)
        table_title = QLabel("🕒 Recent Activity")
        table_title.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        table_title.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # small descriptive label under the card title (like other cards)
        table_small = QLabel("Latest history entries")
        table_small.setObjectName("small")
        table_small.setFont(QFont("Segoe UI", 9))
        table_small.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # assemble the card: title, table, small label
        table_card_layout.addWidget(table_title)
        table_card_layout.addWidget(self.table)
        table_card_layout.addWidget(table_small)
        self.table_card.setLayout(table_card_layout)

        # add to grid in the same spot the table used to be (left column spanning two rows)
        grid.addWidget(self.table_card, 0, 0, 2, 1)
        # ------------------------------------------------------------------------

        # Right column (former positions of rules/users/threats)
        grid.addWidget(self.sites_card, 0, 1)
        grid.addWidget(self.devices_card, 1, 1)
        grid.addWidget(self.sigs_card, 2, 1)

        # Registered users moved to left column below the table (row 2, col 0)
        grid.addWidget(self.users_card, 2, 0)

        # Firewall rules and threats side-by-side below the grid (row 3)
        grid.addWidget(self.rules_card, 3, 0)
        grid.addWidget(self.threats_card, 3, 1)

        # column stretch: give left column slightly more space so table looks prominent
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        # rows may expand as needed
        for r in range(0, 4):
            grid.setRowStretch(r, 0)

        outer.addLayout(grid)

        # scroll area to avoid clipping on small windows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content_widget)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

        # connect click signals (HomePage should wire these to switch tabs)
        self.sites_card.clicked.connect(lambda: self.card_clicked.emit("sites"))
        self.rules_card.clicked.connect(lambda: self.card_clicked.emit("rules"))
        self.devices_card.clicked.connect(lambda: self.card_clicked.emit("devices"))
        self.users_card.clicked.connect(lambda: self.card_clicked.emit("users"))
        self.sigs_card.clicked.connect(lambda: self.card_clicked.emit("signatures"))
        self.threats_card.clicked.connect(lambda: self.card_clicked.emit("threats"))

        # start auto-refresh timer (UI-only). 5 seconds is a reasonable default.
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(5000)  # ms
        self._auto_timer.timeout.connect(self.refresh_summary)
        self._auto_timer.start()

        # initial population
        self.refresh_summary()

    def _make_card(self, title_text: str, big_text: str, small: bool = False) -> ClickableFrame:
        frame = ClickableFrame()
        frame.setObjectName("card")
        frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        v = QVBoxLayout()
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(6)

        title = QLabel(title_text)
        title.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title.setWordWrap(True)

        big = QLabel(big_text)
        big.setObjectName("big")
        big.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        big.setAlignment(Qt.AlignmentFlag.AlignLeft)
        big.setWordWrap(False)

        small_lbl = QLabel("")
        small_lbl.setObjectName("small")
        small_lbl.setFont(QFont("Segoe UI", 9))
        small_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        small_lbl.setWordWrap(True)

        v.addWidget(title)
        v.addWidget(big)
        v.addWidget(small_lbl)
        frame.setLayout(v)

        frame._title = title
        frame._big = big
        frame._small = small_lbl
        return frame

    def _ensure_db_parent(self, db_path):
        if not db_path:
            return
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def refresh_summary(self):
        """
        UI-only refresh: reads DBs and updates cards and table.
        Non-destructive.
        """
        try:
            self._ensure_db_parent(DEFAULT_DB)
            self._ensure_db_parent(USERS_DB)

            # blocked domains / rules
            sites = rules = 0
            try:
                with sqlite3.connect(os.path.abspath(DEFAULT_DB)) as conn:
                    cur = conn.cursor()
                    cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT UNIQUE)")
                    cur.execute("CREATE TABLE IF NOT EXISTS firewall_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port TEXT, protocol TEXT, action TEXT)")
                    cur.execute("SELECT COUNT(*) FROM blocked_domains")
                    sites = cur.fetchone()[0] or 0
                    cur.execute("SELECT COUNT(*) FROM firewall_rules")
                    rules = cur.fetchone()[0] or 0
            except Exception as db_e:
                self.sites_card._big.setText("—")
                self.sites_card._small.setText(f"Error: {db_e}")
                self.rules_card._big.setText("—")
                self.rules_card._small.setText(f"Error: {db_e}")

            # users
            users = 0
            try:
                with sqlite3.connect(os.path.abspath(USERS_DB)) as c2:
                    cur2 = c2.cursor()
                    cur2.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT DEFAULT 'user')")
                    cur2.execute("SELECT COUNT(*) FROM users")
                    users = cur2.fetchone()[0] or 0
            except Exception as user_e:
                self.users_card._big.setText("—")
                self.users_card._small.setText(f"Error: {user_e}")

            # app signatures (best-effort)
            sig_count = 0
            try:
                with sqlite3.connect(os.path.abspath(DEFAULT_DB)) as conn:
                    cur = conn.cursor()
                    cur.execute("CREATE TABLE IF NOT EXISTS app_signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, pattern TEXT)")
                    cur.execute("SELECT COUNT(*) FROM app_signatures")
                    sig_count = cur.fetchone()[0] or 0
            except Exception:
                sig_count = 0

            # threats (try threats.db then fallback to general history)
            threats = 0
            try:
                threats_db = os.path.abspath(os.path.join(os.path.dirname(DEFAULT_DB), "threats.db"))
                if os.path.exists(threats_db):
                    with sqlite3.connect(threats_db) as ct:
                        curt = ct.cursor()
                        curt.execute("CREATE TABLE IF NOT EXISTS threats (id INTEGER PRIMARY KEY AUTOINCREMENT)")
                        curt.execute("SELECT COUNT(*) FROM threats")
                        threats = curt.fetchone()[0] or 0
                else:
                    with sqlite3.connect(os.path.abspath(GENERAL_HISTORY_DB)) as ch:
                        curh = ch.cursor()
                        curh.execute("SELECT COUNT(*) FROM history WHERE action LIKE '%Threat%' OR action LIKE '%threat%'")
                        threats = curh.fetchone()[0] or 0
            except Exception:
                threats = 0

            # live devices count (updated by NetworkControlTab)
            live_devices = 0
            try:
                with sqlite3.connect(os.path.abspath(DEFAULT_DB)) as conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS live_devices
                        (
                            ip
                            TEXT
                            PRIMARY
                            KEY,
                            mac
                            TEXT,
                            vendor
                            TEXT,
                            dev_type
                            TEXT,
                            last_seen
                            TEXT
                        )
                        """
                    )
                    cur.execute("SELECT COUNT(*) FROM live_devices")
                    live_devices = cur.fetchone()[0] or 0
            except Exception:
                live_devices = 0

            # Apply values to cards (only if not already an error)
            try:
                if not self.sites_card._small.text().startswith("Error"):
                    self.sites_card._big.setText(str(sites))
                    self.sites_card._small.setText("Total blocked domains")
            except Exception:
                pass
            try:
                if not self.rules_card._small.text().startswith("Error"):
                    self.rules_card._big.setText(str(rules))
                    self.rules_card._small.setText("Configured firewall rules")
            except Exception:
                pass
            try:
                self.devices_card._big.setText(str(live_devices))
                self.devices_card._small.setText("Devices currently connected to the network")
            except Exception:
                pass

            try:
                if not self.users_card._small.text().startswith("Error"):
                    self.users_card._big.setText(str(users))
                    self.users_card._small.setText("Accounts registered")
            except Exception:
                pass

            try:
                self.sigs_card._big.setText(str(sig_count))
                self.sigs_card._small.setText("Application signatures")
            except Exception:
                pass
            try:
                self.threats_card._big.setText(str(threats))
                self.threats_card._small.setText("Threat log entries")
            except Exception:
                pass

            # Table: last 12 history rows
            try:
                if os.path.exists(os.path.abspath(GENERAL_HISTORY_DB)):
                    with sqlite3.connect(os.path.abspath(GENERAL_HISTORY_DB)) as gdb:
                        gcur = gdb.cursor()
                        gcur.execute("SELECT timestamp, action, description FROM history ORDER BY id DESC LIMIT 12")
                        rows = gcur.fetchall() or []
                        rows = [(r[0] or "", r[1] or "", r[2] or "") for r in rows]
                        self.table.load_data(rows)
                else:
                    self.table.load_data([])
            except Exception:
                try:
                    self.table.load_data([])
                except Exception:
                    pass

        except Exception as e:
            self.sites_card._big.setText("—")
            self.rules_card._big.setText("—")
            self.devices_card._big.setText("—")
            self.users_card._big.setText("—")
            self.sites_card._small.setText(f"Error loading stats: {e}")
