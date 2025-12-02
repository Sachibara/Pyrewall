# pyrewall/ui/tabs/history_tab.py
import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton,
    QHBoxLayout, QMessageBox, QLineEdit, QComboBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import QTimer
from datetime import datetime, timedelta
from pyrewall.ui.button_styles import make_button

DB_PATH = "pyrewall/db/general_history.db"

class HistoryTab(QWidget):
    """Displays system actions and event logs in real-time with search (archives are preserved)."""
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

        # ---------- Search row (single horizontal line) ----------
        search_row = QHBoxLayout()

        # Search input (shortened so buttons fit on same row)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search username / action / description or date (e.g. 2025-11-29 or 2025-11-01..2025-11-10)")
        self.search_input.setFixedWidth(420)
        self.search_input.textChanged.connect(self._on_search_text_changed)
        search_row.addWidget(self.search_input)

        # Sort order (Ascending / Descending)
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Descending", "Ascending"])
        self.sort_combo.setFixedWidth(120)
        search_row.addWidget(self.sort_combo)

        self.search_btn = make_button("Search", variant="primary", height=30, width=120)
        self.search_btn.clicked.connect(self.perform_search)
        search_row.addWidget(self.search_btn)

        # Admin-only: Archive Old Logs button placed beside search button
        if self.role == "admin":
            self.archive_btn = make_button("🗄️ Archive Old Logs", variant="warning", height=30, width=150)
            self.archive_btn.clicked.connect(self.archive_old_logs)
            search_row.addWidget(self.archive_btn)

        layout.addLayout(search_row)

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
        # connect sort changes AFTER UI creation to avoid triggering before ready
        self.sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        self.load_logs(first=True)

        # ---------- Timer for Instant Updates ----------
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_for_updates)
        self.timer.start(1000)  # every 1 second

    # ==========================================================
    # Database Setup
    # ==========================================================
    def _init_db(self):
        """Ensure general_history and archive table exist."""
        try:
            os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
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
            # archive table (preserves original row + archived_at)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS archived_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    orig_id INTEGER,
                    username TEXT,
                    action TEXT,
                    description TEXT,
                    timestamp DATETIME,
                    archived_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
        """Instantly refresh when a new log entry appears, unless user has an active search."""
        # If search box is non-empty we pause live updates
        if self.search_input.text().strip():
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM history")
            count = cur.fetchone()[0] or 0
            conn.close()

            if count != self.last_count:
                self.load_logs()
        except Exception:
            pass

    def _current_order_sql(self) -> str:
        """Return 'ASC' or 'DESC' according to sort_combo."""
        return "DESC" if self.sort_combo.currentText().lower().startswith("desc") else "ASC"

    def load_logs(self, first=False, rows=None):
        """
        Load logs from the database into the list.
        If 'rows' is provided, it will display those rows instead of querying DB (used by search).
        """
        try:
            order = self._current_order_sql()

            if rows is None:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                # use ORDER BY timestamp so chronological order is consistent; respect sort_combo
                cur.execute(f"SELECT username, action, description, timestamp FROM history ORDER BY timestamp {order} LIMIT 200")
                rows = cur.fetchall()
                conn.close()

            # If rows were provided by search, they are already ordered by perform_search's ORDER clause.
            # If the caller provided rows but wishes to re-order according to the combo, we could sort them here,
            # but perform_search already respects the sort. For live view we used ORDER BY in SQL above.

            self.log_list.clear()

            if not rows:
                self.log_list.addItem("(No logs yet)")
                return

            # If rows came from DB in ascending order (oldest first), we may want newest at top for 'descending' view
            # but since SQL already respected order, just display in given order.
            for username, action, desc, ts in rows:
                formatted = f"[{ts}] 👤 {username:<12} | ⚙️ {action:<15} | 📝 {desc}"
                self.log_list.addItem(formatted)

            # update last_count only when showing live history (i.e. no active search)
            if not self.search_input.text().strip():
                if first:
                    self.last_count = len(rows)
                else:
                    # best-effort: refresh count value
                    try:
                        conn = sqlite3.connect(DB_PATH)
                        cur = conn.cursor()
                        cur.execute("SELECT COUNT(*) FROM history")
                        self.last_count = cur.fetchone()[0] or 0
                        conn.close()
                    except Exception:
                        self.last_count = len(rows)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load logs:\n{e}")

    # ==========================================================
    # Archive Logs (Admin only, logs older than 1 minute)
    # ==========================================================
    def archive_old_logs(self):
        """
        Move logs older than the cutoff from 'history' to 'archived_history'
        (non-destructive). Cutoff currently 1 minute (UTC).
        """
        confirm = QMessageBox.question(self, "Confirm", "Archive logs older than 1 minute? (they will be preserved in the archive)")
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=1)
            cutoff_str = cutoff_time.strftime("%Y-%m-%d %H:%M:%S")

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()

            # 1) select rows to archive
            cur.execute(
                "SELECT id, username, action, description, timestamp FROM history WHERE timestamp <= ?",
                (cutoff_str,)
            )
            rows_to_archive = cur.fetchall()
            if not rows_to_archive:
                conn.close()
                QMessageBox.information(self, "Info", "No logs older than 1 minute found to archive.")
                return

            # 2) insert into archived_history (preserve original id as orig_id)
            cur.executemany(
                "INSERT INTO archived_history (orig_id, username, action, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                [(r[0], r[1], r[2], r[3], r[4]) for r in rows_to_archive]
            )

            # 3) delete those rows from history
            ids = [r[0] for r in rows_to_archive]
            placeholders = ",".join("?" for _ in ids)
            cur.execute(f"DELETE FROM history WHERE id IN ({placeholders})", ids)

            conn.commit()
            conn.close()

            QMessageBox.information(self, "Archived", f"🗄️ Archived {len(ids)} log(s) successfully.")
            self.load_logs()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to archive old logs:\n{e}")

    # ==========================================================
    # Search / Helpers
    # ==========================================================
    def _on_search_text_changed(self, txt):
        """
        Pause auto-refresh while there's an active search input.
        If user clears the box, resume live updates and reload latest logs.
        """
        if txt.strip():
            # user typing -> pause timer
            if self.timer.isActive():
                self.timer.stop()
        else:
            # empty -> resume and reload live logs
            if not self.timer.isActive():
                self.timer.start(1000)
            self.load_logs()

    def _on_sort_changed(self, index):
        """
        Called when sort order dropdown changes.
        If a search is active, re-run the search to apply the new order.
        Otherwise reload live logs with new order.
        """
        if self.search_input.text().strip():
            # re-run search so results respect new sort
            try:
                self.perform_search()
            except Exception:
                pass
        else:
            # reload live logs in chosen order
            try:
                self.load_logs()
            except Exception:
                pass

    def perform_search(self):
        """
        Build a query to search the `history` table only (archived table is NOT searched).
        Supported date inputs in the search box:
          - single ISO date: YYYY-MM-DD  -> searches that entire day (UTC)
          - single datetime: YYYY-MM-DD HH:MM or YYYY-MM-DDTHH:MM
          - range: START..END where START and END are dates or datetimes (use '..' separator)
        Examples:
          - "admin" (search username/action/description)
          - "2025-11-29" (all logs on Nov 29 2025)
          - "2025-11-01..2025-11-10"
          - "login 2025-11-29"
        """
        raw = self.search_input.text().strip()
        if not raw:
            QMessageBox.information(self, "Search", "Enter a search query or date.")
            return

        # parse sort order
        order = "DESC" if self.sort_combo.currentText().lower().startswith("desc") else "ASC"

        # Detect date range syntax using '..'
        start_dt = end_dt = None
        query_terms = raw

        if ".." in raw:
            parts = [p.strip() for p in raw.split("..", 1)]
            start_dt = self._parse_date_flexible(parts[0])
            end_dt = self._parse_date_flexible(parts[1])
            # remove parsed parts from query_terms if we can
            # (user likely only wants date range, otherwise we keep full raw text too)
            if start_dt or end_dt:
                query_terms = raw  # keep original to allow combined searches
        else:
            # try to find a single date token at start or end
            tokens = raw.split()
            for t in (tokens[0], tokens[-1]) if tokens else []:
                parsed = self._parse_date_flexible(t)
                if parsed:
                    # single date provided: treat as that day (start..end of day) unless time included
                    if isinstance(parsed, tuple):
                        # parsed as (start, end)
                        start_dt, end_dt = parsed
                    else:
                        # single date -> expand to day range
                        d = parsed
                        start_of_day = datetime(d.year, d.month, d.day, 0, 0, 0)
                        end_of_day = datetime(d.year, d.month, d.day, 23, 59, 59)
                        start_dt, end_dt = start_of_day, end_of_day
                    # keep query_terms unchanged to still allow text search
                    break

        # Build SQL
        sql = "SELECT username, action, description, timestamp FROM history"
        where_clauses = []
        params = []

        # text matching across username/action/description (case-insensitive using LIKE)
        like_term = f"%{raw.replace('%','\\%')}%"
        where_clauses.append("(username LIKE ? OR action LIKE ? OR description LIKE ?)")
        params.extend([like_term, like_term, like_term])

        # if we detected date range, add timestamp constraints
        if start_dt is not None or end_dt is not None:
            # ensure we have explicit bounds
            if start_dt is None:
                start_dt = datetime(1970, 1, 1)
            if end_dt is None:
                end_dt = datetime.utcnow()
            where_clauses.append("(timestamp BETWEEN ? AND ?)")
            params.append(start_dt.strftime("%Y-%m-%d %H:%M:%S"))
            params.append(end_dt.strftime("%Y-%m-%d %H:%M:%S"))

        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)

        sql += f" ORDER BY timestamp {order} LIMIT 500"

        # Execute query and display results
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            conn.close()

            # show results (pause auto refresh while search active - ensured elsewhere)
            self.load_logs(rows=rows)
        except Exception as e:
            QMessageBox.critical(self, "Search Error", f"Failed to perform search:\n{e}")

    def _parse_date_flexible(self, token):
        """
        Try parsing a token as a date or datetime.
        Returns:
          - a datetime object (date parsed),
          - OR a tuple (start_dt, end_dt) if token looked like a date-only and should expand to a range,
          - OR None if parsing failed.
        Accepts formats:
          YYYY-MM-DD
          YYYY/MM/DD
          YYYY-MM-DDTHH:MM
          YYYY-MM-DD HH:MM
          YYYY-MM-DD HH:MM:SS
        """
        if not token or token.lower() in ("and", "to"):
            return None
        # normalize separators
        t = token.replace("/", "-").replace("t", "T")
        fmts = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d"
        ]
        for f in fmts:
            try:
                dt = datetime.strptime(t, f)
                # if format is date-only, return that date to be expanded by caller
                if f == "%Y-%m-%d":
                    return dt
                return dt
            except Exception:
                continue
        return None
