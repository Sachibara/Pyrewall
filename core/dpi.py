"""
Deep Packet Inspection (DPI) basic engine.
Identifies app protocols by signature.
"""

import re

def identify_protocol(payload: bytes) -> str:
    """Return guessed application type from payload."""
    text = payload.decode(errors="ignore").lower()
    if "facebook" in text:
        return "Facebook"
    if "youtube" in text:
        return "YouTube"
    if "tiktok" in text:
        return "TikTok"
    if "spotify" in text:
        return "Spotify"
    if "ssl" in text or "https" in text:
        return "HTTPS"
    return "Unknown"

def detect_sensitive_keywords(payload: bytes):
    """Detect specific keywords for IDS triggers."""
    keywords = ["password", "login", "token", "api_key"]
    text = payload.decode(errors="ignore").lower()
    return [kw for kw in keywords if kw in text]
