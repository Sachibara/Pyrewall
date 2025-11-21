"""
Tracks active network connections in memory.
Used for real-time visualization and session control.
"""

import threading
from datetime import datetime

class ConnectionTable:
    def __init__(self):
        self.lock = threading.Lock()
        self.connections = {}  # {conn_id: {src, dst, protocol, timestamp}}

    def add(self, src, dst, protocol):
        conn_id = f"{src}->{dst}-{protocol}"
        with self.lock:
            self.connections[conn_id] = {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    def remove(self, conn_id):
        with self.lock:
            self.connections.pop(conn_id, None)

    def get_all(self):
        with self.lock:
            return dict(self.connections)
