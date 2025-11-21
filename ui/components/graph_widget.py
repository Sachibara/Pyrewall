from PyQt6.QtWidgets import QWidget, QVBoxLayout
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class GraphWidget(QWidget):
    """Reusable live graph widget."""
    def __init__(self, title="Traffic Graph"):
        super().__init__()
        layout = QVBoxLayout()
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        self.setLayout(layout)

    def update_graph(self, data):
        ax = self.figure.add_subplot(111)
        ax.clear()
        ax.plot(data, label="Traffic")
        ax.legend()
        self.canvas.draw()
