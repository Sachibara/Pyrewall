"""
Detect VPN or DoH traffic patterns.
"""

VPN_PORTS = [1194, 51820, 443, 500, 1701]
VPN_KEYWORDS = ["vpn", "openvpn", "wireguard", "ipsec"]

def detect_vpn(packet):
    if getattr(packet, "dst_port", None) in VPN_PORTS:
        return True
    payload = bytes(packet.payload or b"").lower()
    if any(k.encode() in payload for k in VPN_KEYWORDS):
        return True
    return False
