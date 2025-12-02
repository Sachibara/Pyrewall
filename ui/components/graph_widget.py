# pyrewall/ui/components/graph_widget.py
from collections import deque
from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import QTimer
# Prefer qtagg backend for modern matplotlib; fall back to qt5agg
try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
except Exception:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from typing import Optional, Callable, Iterable

class GraphWidget(QWidget):
    """
    Rolling download/upload time-series graph.

    Usage:
      gw = GraphWidget(title="Traffic", max_points=60, max_mbps=1000)
      gw.push_sample(12.3, 3.4)
      gw.start_live(callback=my_callback, interval_ms=1000)  # callback -> (dl, ul) or single number or None
    """
    def __init__(self, title: str = "Traffic Graph", max_points: int = 60, max_mbps: float = 1000.0):
        super().__init__()
        self.title = title
        self.max_points = max(1, int(max_points))
        self.max_mbps = float(max(1.0, max_mbps))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.figure = Figure(figsize=(5, 2.2), tight_layout=True)
        self.canvas = FigureCanvas(self.figure)
        # after creating self.canvas in __init__, force an initial draw
        layout.addWidget(self.canvas)
        # ensure widget paints at least once
        try:
            self.canvas.draw()
        except Exception:
            # fallback: draw_idle if draw() unsupported
            try:
                self.canvas.draw_idle()
            except Exception:
                pass

        # Axes and lines
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title(self.title)
        self.ax.grid(True, linewidth=0.6, alpha=0.7)
        self.ax.set_xlabel("Samples (new → right)")
        self.ax.set_ylabel("Mbps")

        # Buffers (right-aligned history)
        self.download = deque([0.0] * self.max_points, maxlen=self.max_points)
        self.upload = deque([0.0] * self.max_points, maxlen=self.max_points)

        # Plot objects (empty initial data)
        (self.line_dl,) = self.ax.plot([], [], label="Download", linewidth=2.2)
        (self.line_ul,) = self.ax.plot([], [], label="Upload", linewidth=2.2)
        self.ax.legend(loc="upper right", fontsize=9)

        # Initial axis limits
        self.ax.set_xlim(0, max(1, self.max_points - 1))
        self.ax.set_ylim(0, max(10.0, self.max_mbps))

        # Live update timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer_tick)
        self._live_callback: Optional[Callable[[], Optional[Iterable[float]]]] = None

        # initial draw
        self._redraw()

    # ---------- Data ingestion ----------
    def push_sample(self, download_mbps: float, upload_mbps: float):
        """Append a single (download, upload) sample. Values clamped to [0, max_mbps]."""
        try:
            dl = 0.0 if download_mbps is None else float(download_mbps)
        except Exception:
            dl = 0.0
        try:
            ul = 0.0 if upload_mbps is None else float(upload_mbps)
        except Exception:
            ul = 0.0

        dl = max(0.0, min(dl, self.max_mbps))
        ul = max(0.0, min(ul, self.max_mbps))

        self.download.append(dl)
        self.upload.append(ul)
        self._redraw()

    def update_graph(self, data):
        """
        Backwards-compatible updater:
         - If data is (dl, ul) or [dl, ul] -> push_sample
         - If data is a single numeric -> push_sample(data, 0.0)
         - If data is a list/iterable of numbers -> treat as a historic single series, right-align into download buffer
        """
        if data is None:
            return
        try:
            # tuple/list two numeric values -> sample
            if isinstance(data, (list, tuple)):
                if len(data) == 2 and all(isinstance(x, (int, float)) for x in data):
                    self.push_sample(data[0], data[1])
                    return
                # Otherwise treat as single historic numeric series
                try:
                    nums = [float(x) for x in data]
                except Exception:
                    return
                # right-align into download buffer, leave upload as-is
                pad = max(0, self.max_points - len(nums))
                fill = [0.0] * pad + nums[-self.max_points:]
                self.download = deque(fill, maxlen=self.max_points)
                self._redraw()
                return
            # single numeric
            if isinstance(data, (int, float)):
                self.push_sample(float(data), 0.0)
                return
        except Exception:
            # ignore bad update payloads
            return

    # ---------- Live control ----------
    def start_live(self, callback: Optional[Callable[[], Optional[Iterable[float]]]] = None, interval_ms: int = 1000):
        """
        Start auto-tick. `callback()` should return (dl, ul) or a single numeric or None.
        If callback is None, timer will only call redraw (useful if external code pushes samples).
        """
        self._live_callback = callback
        self._timer.start(int(interval_ms))

    def stop_live(self):
        self._timer.stop()
        self._live_callback = None

    def _on_timer_tick(self):
        if callable(self._live_callback):
            try:
                result = self._live_callback()
            except Exception:
                result = None
            if result is None:
                self._redraw()
                return
            # accept (dl, ul), single numeric, or ignore
            try:
                if isinstance(result, (list, tuple)) and len(result) >= 2:
                    self.push_sample(result[0], result[1])
                elif isinstance(result, (int, float)):
                    self.push_sample(result, 0.0)
                else:
                    self._redraw()
            except Exception:
                self._redraw()
        else:
            self._redraw()

    # ---------- Rendering ----------
    def _redraw(self):
        try:
            dl = list(self.download)
            ul = list(self.upload)

            # x indices: 0 .. n-1 (right aligned: newest at the end)
            n = max(1, len(dl))
            x = list(range(n))

            # update line data
            self.line_dl.set_data(x, dl)
            self.line_ul.set_data(x, ul)

            # recompute data limits and autoscale
            try:
                # update internal data limits then autoscale view
                self.ax.relim()
                self.ax.autoscale_view(scalex=False, scaley=True)
            except Exception:
                pass

            # autoscale y with some headroom, but clamp at max_mbps
            current_max = max(max(dl) if dl else 0.0, max(ul) if ul else 0.0, 10.0)
            y_top = min(max(current_max * 1.15, 10.0), self.max_mbps)
            self.ax.set_ylim(0.0, y_top)

            # x limits: show full buffer length (if single point, show small range)
            if n <= 1:
                self.ax.set_xlim(0.0, max(1.0, self.max_points - 1))
            else:
                self.ax.set_xlim(0.0, max(n - 1, 1))

            # redraw (try draw_idle, fallback to draw)
            try:
                self.canvas.draw_idle()
            except Exception:
                try:
                    self.canvas.draw()
                except Exception as e:
                    print(f"[GraphWidget] draw fallback error: {e}")
        except Exception as e:
            import traceback
            print(f"[GraphWidget] redraw error: {e}")
            traceback.print_exc()
