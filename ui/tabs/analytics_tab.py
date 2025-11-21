import os
import sqlite3
from datetime import datetime, timedelta
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QMessageBox
from PyQt6.QtGui import QFont
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

DB_PATH = "pyrewall/db/general_history.db"


class AnalyticsTab(QWidget):
    """Displays charts of user activity and firewall events."""
    def __init__(self, username):
        super().__init__()
        self.username = username

        layout = QVBoxLayout()
        title = QLabel("📈 System Analytics & Insights")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Create figure and canvas for matplotlib
        self.figure = Figure(figsize=(6, 4))
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.setLayout(layout)
        self.load_data_and_plot()

    def load_data_and_plot(self):
        """Load recent data and plot basic statistics."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, action FROM history
                WHERE timestamp >= datetime('now', '-7 days')
                ORDER BY timestamp ASC
            """)
            rows = cur.fetchall()
            conn.close()

            if not rows:
                self.figure.clear()
                ax = self.figure.add_subplot(111)
                ax.text(0.5, 0.5, "No activity logs in the past 7 days.",
                        ha="center", va="center", fontsize=12, color="gray")
                self.canvas.draw()
                return

            # Group actions per day
            daily_actions = {}
            for ts, action in rows:
                date = ts.split(" ")[0]
                daily_actions[date] = daily_actions.get(date, 0) + 1

            dates = sorted(daily_actions.keys())
            counts = [daily_actions[d] for d in dates]

            # --- Plot ---
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            ax.bar(dates, counts, color="#0078D7")
            ax.set_title("User Activity (Past 7 Days)", fontsize=12, fontweight="bold")
            ax.set_xlabel("Date")
            ax.set_ylabel("Actions Logged")
            ax.tick_params(axis="x", rotation=45)
            self.figure.tight_layout()
            self.canvas.draw()

        except Exception as e:
            QMessageBox.critical(self, "Analytics Error", f"Failed to load analytics:\n{e}")
