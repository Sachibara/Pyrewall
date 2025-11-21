from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

class TableWidget(QTableWidget):
    """Reusable table for log/history data."""
    def __init__(self, headers):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)

    def load_data(self, rows):
        self.setRowCount(len(rows))
        for r, row_data in enumerate(rows):
            for c, val in enumerate(row_data):
                self.setItem(r, c, QTableWidgetItem(str(val)))
