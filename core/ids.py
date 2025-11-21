"""
Intrusion Detection System (signature-based).
Scans payloads for known malicious patterns.
"""

from pyrewall.core.dpi import detect_sensitive_keywords

class IntrusionDetection:
    def __init__(self):
        self.alerts = []

    def analyze_packet(self, packet):
        payload = bytes(packet.payload or b"")
        matches = detect_sensitive_keywords(payload)
        if matches:
            alert = {
                "type": "Sensitive Data",
                "details": ", ".join(matches),
                "src": str(packet.src_addr),
                "dst": str(packet.dst_addr)
            }
            self.alerts.append(alert)
            return alert
        return None

    def get_alerts(self):
        return list(self.alerts)
