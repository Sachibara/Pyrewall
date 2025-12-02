"""
Intrusion Prevention System (IPS)
Drops packets detected as malicious by IDS.
"""

from pyrewall.core.ids import IntrusionDetection

class IntrusionPrevention:
    def __init__(self):
        self.ids = IntrusionDetection()
        self.blocked_ips = set()

    def inspect(self, packet):
        alert = self.ids.analyze_packet(packet)
        if alert:
            self.blocked_ips.add(alert["src"])
            return False  # drop packet
        return True  # allow packet
