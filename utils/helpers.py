import os
import sys
import re

def resource_path(*parts):
    """
    Return an absolute path to a bundled resource.
    Works for normal execution and for PyInstaller onefile/extracted bundle.
    Usage: resource_path("assets", "dll", "WinDivert.dll")
    """
    if getattr(sys, "frozen", False):
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base, *parts)


def is_valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern, ip) is not None

def is_valid_domain(domain):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
    return re.match(pattern, domain) is not None
