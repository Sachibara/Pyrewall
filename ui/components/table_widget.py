# pyrewall/ui/components/table_widget.py
from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QFileDialog, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
import csv
import io
import traceback
import threading

class TableWidget(QTableWidget):
    """
    Reusable read-only table suitable for log/history views with convenient features:
      - read-only rows by default
      - alternating row colors
      - single-row selection (can change after init)
      - automatic column stretch
      - load_data(rows) to replace contents (rows = list of iterables)
      - append_row(row) to add a single row
      - export_csv(path) to write a CSV
      - right-click context menu: Copy selected / Copy all / Export CSV / Select All
      - double-click emits row_double_clicked(row_index, row_values)
    """

    row_double_clicked = pyqtSignal(int, list)  # row index, list of values

    def __init__(self, headers=None, readonly: bool = True, stretch: bool = True):
        headers = headers or []
        super().__init__(0, len(headers))
        self._readonly = readonly

        # headers
        if headers:
            self.setColumnCount(len(headers))
            self.setHorizontalHeaderLabels([str(h) for h in headers])
        else:
            # keep columns at 0 until data arrives
            self.setColumnCount(0)

        # appearance / behavior
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.verticalHeader().setVisible(False)
        # default to enabled; code will temporarily disable while populating
        self.setSortingEnabled(True)

        # default resize policy
        try:
            if stretch and self.columnCount() > 0:
                self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
                self.horizontalHeader().setStretchLastSection(True)
            elif self.columnCount() > 0:
                self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        except Exception:
            # defensive: print stack for debugging
            traceback.print_exc()

        # disable editing if requested
        if readonly:
            self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # enable context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _call_on_main_thread(self, fn, *args, **kwargs):
        """If called from a non-main thread, schedule on the Qt main thread."""
        if threading.current_thread() is threading.main_thread():
            return fn(*args, **kwargs)
        else:
            # schedule on the main thread (single shot)
            QTimer.singleShot(0, lambda: fn(*args, **kwargs))
            return None

    # ---------------------------
    # Data population API
    # ---------------------------
    def load_data(self, rows, headers=None):
        """
        Replace table contents with rows (iterable of iterables/tuples).
        Optionally update headers (iterable).
        If called from a non-main thread, will schedule on the GUI thread.
        """
        # if not on main thread, schedule it and return
        if threading.current_thread() is not threading.main_thread():
            return self._call_on_main_thread(self.load_data, rows, headers)

        sorting_was_enabled = False
        try:
            rows = rows or []

            # temporarily disable sorting to avoid internal reindex issues
            try:
                sorting_was_enabled = self.isSortingEnabled()
                if sorting_was_enabled:
                    self.setSortingEnabled(False)
            except Exception:
                sorting_was_enabled = False

            # reduce repainting and signals while populating
            try:
                self.setUpdatesEnabled(False)
                self.blockSignals(True)
            except Exception:
                pass

            # optional header update
            if headers is not None:
                headers = list(headers)
                self.setColumnCount(len(headers))
                self.setHorizontalHeaderLabels([str(h) for h in headers])

            # If no headers but rows exist, infer columns from first row
            if self.columnCount() == 0 and rows:
                first = rows[0]
                try:
                    colcount = len(first)
                except Exception:
                    # fallback: treat as single column
                    colcount = 1
                self.setColumnCount(colcount)

            # clear existing contents safely
            try:
                self.clearContents()
                self.setRowCount(0)
            except Exception:
                traceback.print_exc()

            # set rows
            self.setRowCount(len(rows))
            for r, row in enumerate(rows):
                for c in range(self.columnCount()):
                    try:
                        if row is None:
                            val = ""
                        else:
                            # handle sequences and single scalars
                            try:
                                val = row[c] if c < len(row) else ""
                            except Exception:
                                val = str(row)
                    except Exception:
                        val = str(row)
                    item = QTableWidgetItem("" if val is None else str(val))
                    if self._readonly:
                        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.setItem(r, c, item)

            # visual adjustments
            try:
                self.resizeRowsToContents()
                # guard header access if no columns
                if self.columnCount() > 0:
                    # if using stretch preference, set it
                    try:
                        mode = self.horizontalHeader().sectionResizeMode(0)
                        # if mode isn't ResizeToContents, set to Stretch (keeps readable)
                        if mode != QHeaderView.ResizeMode.ResizeToContents:
                            self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
                    except Exception:
                        # if sectionResizeMode failed, just try a safe Stretch
                        try:
                            self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
                        except Exception:
                            pass
            except Exception:
                traceback.print_exc()

            # show top row
            if self.rowCount() > 0:
                self.scrollToTop()

        except Exception:
            traceback.print_exc()
        finally:
            # restore sorting & signals & updates
            try:
                if sorting_was_enabled:
                    self.setSortingEnabled(True)
            except Exception:
                pass
            try:
                self.blockSignals(False)
                self.setUpdatesEnabled(True)
            except Exception:
                pass

    def append_row(self, row):
        """Append a single row (iterable)."""
        # if not on main thread, schedule it and return
        if threading.current_thread() is not threading.main_thread():
            return self._call_on_main_thread(self.append_row, row)

        sorting_was_enabled = False
        try:
            # temporarily disable sorting to avoid internal reindex issues
            try:
                sorting_was_enabled = self.isSortingEnabled()
                if sorting_was_enabled:
                    self.setSortingEnabled(False)
            except Exception:
                sorting_was_enabled = False

            try:
                self.setUpdatesEnabled(False)
                self.blockSignals(True)
            except Exception:
                pass

            # if no columns defined, try to infer from row
            if self.columnCount() == 0:
                try:
                    colcount = len(row)
                except Exception:
                    colcount = 1
                self.setColumnCount(colcount)

            r = self.rowCount()
            self.insertRow(r)
            for c in range(self.columnCount()):
                try:
                    val = "" if row is None else (row[c] if c < len(row) else "")
                except Exception:
                    val = str(row)
                item = QTableWidgetItem("" if val is None else str(val))
                if self._readonly:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.setItem(r, c, item)
            try:
                self.resizeRowToContents(r)
            except Exception:
                pass
            self.scrollToBottom()
        except Exception:
            traceback.print_exc()
        finally:
            # restore sorting state, updates and signals
            try:
                if sorting_was_enabled:
                    self.setSortingEnabled(True)
            except Exception:
                pass
            try:
                self.blockSignals(False)
                self.setUpdatesEnabled(True)
            except Exception:
                pass

    # ---------------------------
    # Utilities
    # ---------------------------
    def to_csv_string(self, include_headers=True):
        """Return CSV content as a string (UTF-8)."""
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            if include_headers and self.columnCount():
                headers = [
                    self.horizontalHeaderItem(c).text() if self.horizontalHeaderItem(c) else ""
                    for c in range(self.columnCount())
                ]
                writer.writerow(headers)
            for r in range(self.rowCount()):
                row = [self.item(r, c).text() if self.item(r, c) else "" for c in range(self.columnCount())]
                writer.writerow(row)
            return output.getvalue()
        except Exception:
            traceback.print_exc()
            return ""

    def export_csv(self, path=None, include_headers=True):
        """
        Export table contents to CSV. If path is None, shows a save dialog (returns path or None).
        Returns the path if saved, else None.
        """
        try:
            if path is None:
                dlg = QFileDialog(self, "Export Table as CSV")
                dlg.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
                dlg.setNameFilter("CSV files (*.csv);;All files (*)")
                if dlg.exec():
                    files = dlg.selectedFiles()
                    if files:
                        path = files[0]
            if not path:
                return None
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                if include_headers and self.columnCount():
                    headers = [
                        self.horizontalHeaderItem(c).text() if self.horizontalHeaderItem(c) else ""
                        for c in range(self.columnCount())
                    ]
                    writer.writerow(headers)
                for r in range(self.rowCount()):
                    row = [self.item(r, c).text() if self.item(r, c) else "" for c in range(self.columnCount())]
                    writer.writerow(row)
            return path
        except Exception:
            traceback.print_exc()
            return None

    # ---------------------------
    # Interaction: copy / context menu / double click
    # ---------------------------
    def contextMenuEvent(self, event):
        try:
            menu = QMenu(self)
            copy_action = menu.addAction("Copy selected")
            copy_all_action = menu.addAction("Copy all")
            export_action = menu.addAction("Export as CSV...")
            select_all_action = menu.addAction("Select All Rows")
            action = menu.exec(event.globalPos())

            if action == copy_action:
                self._copy_selected_to_clipboard()
            elif action == copy_all_action:
                self._copy_all_to_clipboard()
            elif action == export_action:
                self.export_csv(None)
            elif action == select_all_action:
                self.selectAll()
        except Exception:
            traceback.print_exc()

    def _copy_selected_to_clipboard(self):
        try:
            sel = self.selectedIndexes()
            if not sel:
                return
            rows = {}
            for idx in sel:
                rows.setdefault(idx.row(), {})[idx.column()] = self.item(idx.row(), idx.column()).text() if self.item(idx.row(), idx.column()) else ""
            out_lines = []
            for r in sorted(rows.keys()):
                cols = [rows[r].get(c, "") for c in range(self.columnCount())]
                out_lines.append("\t".join(cols))
            text = "\n".join(out_lines)
            clipboard = self._get_clipboard()
            clipboard.setText(text)
        except Exception:
            traceback.print_exc()

    def _copy_all_to_clipboard(self):
        try:
            text = self.to_csv_string(include_headers=True)
            clipboard = self._get_clipboard()
            clipboard.setText(text)
        except Exception:
            traceback.print_exc()

    def _get_clipboard(self):
        # QGuiApplication.clipboard() available via QApplication.instance()
        return QApplication.instance().clipboard()

    def mouseDoubleClickEvent(self, ev):
        """Emit row_double_clicked with row index and row values list on double-click."""
        try:
            # Qt6: ev.position() returns QPointF; ev.pos() returns QPoint - try both safely
            try:
                idx = self.indexAt(ev.position().toPoint())
            except Exception:
                idx = self.indexAt(ev.pos())
            if idx.isValid():
                r = idx.row()
                values = [self.item(r, c).text() if self.item(r, c) else "" for c in range(self.columnCount())]
                try:
                    self.row_double_clicked.emit(r, values)
                except Exception:
                    pass
        except Exception:
            traceback.print_exc()
        super().mouseDoubleClickEvent(ev)

    def clear(self):
        """Clear all rows and headers."""
        try:
            self.clearContents()
            self.setRowCount(0)
            self.setColumnCount(0)
        except Exception:
            traceback.print_exc()
