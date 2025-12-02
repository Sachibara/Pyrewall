# pyrewall/core/device_identify.py
# Best-effort device fingerprinting: OUI lookup + NetBIOS + SSDP + simple banner grabs
# Returns a small dict: { "ip", "mac", "vendor", "type", "os", "model", "name", "evidence" }

import csv
import os
import re
import socket
import subprocess
import threading
import time

_OUI_CACHE = {}
_VENDOR_CSV = os.path.join(os.path.dirname(__file__), "..", "assets", "mac_vendors.csv")
_LOCK = threading.Lock()

def _load_oui():
    """Load vendor OUI map from CSV (cached). Thread-safe."""
    global _OUI_CACHE
    if _OUI_CACHE:
        return
    path = _VENDOR_CSV  # _VENDOR_CSV already defined above
    path = os.path.abspath(path)
    if not os.path.exists(path):
        # minimal fallback
        _OUI_CACHE.update({
            "00:1A:2B": "Apple",
            "00:1B:63": "HP",
            "00:25:9C": "Samsung",
            "F4:5C:89": "Xiaomi",
        })
        return
    with _LOCK:
        # double-check inside lock
        if _OUI_CACHE:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if len(row) >= 2:
                        k = row[0].strip().upper()
                        _OUI_CACHE[k] = row[1].strip()
        except Exception:
            # fallback minimal
            _OUI_CACHE.update({"00:1A:2B": "Apple"})


def lookup_oui(mac):
    """Return vendor from MAC (best-effort)."""
    if not mac:
        return None
    _load_oui()
    mac_norm = mac.upper().replace("-", ":")
    prefix = mac_norm[:8]
    return _OUI_CACHE.get(prefix) or _OUI_CACHE.get(prefix.replace(":", "-"))

def _nbtstat_name(ip, timeout=1.0):
    """Try NetBIOS name via nbtstat -A <ip> (Windows)."""
    try:
        out = subprocess.check_output(["nbtstat", "-A", ip], text=True, encoding="utf-8", errors="ignore", timeout=timeout)
        # search for "UNIQUE" name line or "<00>" or "<20>" usually the machine name
        m = re.search(r"^\s*([^\s]+)\s+<\d+>\s+UNIQUE", out, re.M)
        if m:
            return m.group(1).strip()
        # fallback parse lines containing '<00>' etc.
        m2 = re.search(r"^\s*([^ \r\n]+)\s+<00>\s+UNIQUE", out, re.M)
        if m2:
            return m2.group(1).strip()
    except Exception:
        pass
    return None

def _ssdp_probe(ip, timeout=0.7):
    """
    Send a quick multicast M-SEARCH and listen for responses - parse those that come from target ip.
    This will sometimes return a friendly device name or server string.
    """
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST:239.255.255.250:1900\r\n'
        'MAN:"ssdp:discover"\r\n'
        'MX:1\r\n'
        'ST:ssdp:all\r\n\r\n'
    ).encode("utf-8")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            if addr[0] != ip:
                continue
            txt = data.decode("utf-8", errors="ignore")
            # look for SERVER: or USN: or LOCATION:
            server = None
            m = re.search(r"(?im)^server:\s*(.+)$", txt)
            if m:
                server = m.group(1).strip()
            else:
                m2 = re.search(r"(?im)^st:\s*(.+)$", txt)
                server = m2.group(1).strip() if m2 else None
            s.close()
            return server
        s.close()
    except Exception:
        pass
    return None

def _banner_grab(ip, ports=(80, 8080, 8000, 554, 22), timeout=0.6):
    """Try connecting to common ports, return any textual banner hints."""
    banners = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, p))
            # If HTTP-ish, send HEAD
            if p in (80, 8080, 8000):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                    data = s.recv(1024)
                    banners.append(data.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            else:
                try:
                    data = s.recv(512)
                    banners.append(data.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            s.close()
        except Exception:
            continue
    return "\n".join(banners)

# small in-memory cache so we don't hit each device on every scan
_IDENTIFY_CACHE = {}
_CACHE_TTL = 30  # seconds

def identify_device(ip, mac):
    """
    Best-effort identification. Returns a dict:
    { ip, mac, vendor, type, os, model, name, evidence }
    """
    key = f"{ip}|{mac}"
    now = time.time()
    # cached?
    entry = _IDENTIFY_CACHE.get(key)
    if entry and now - entry.get("_ts", 0) < _CACHE_TTL:
        return entry

    result = {"ip": ip, "mac": mac or "Unknown", "vendor": None, "type": "Unknown", "os": None, "model": None, "name": None, "evidence": []}
    # OUI vendor
    if mac:
        vendor = lookup_oui(mac)
        if vendor:
            result["vendor"] = vendor
            result["evidence"].append(f"OUI:{vendor}")

    # NetBIOS name (Windows hosts / some Android file sharing apps)
    name = _nbtstat_name(ip)
    if name:
        result["name"] = name
        result["evidence"].append(f"NetBIOS:{name}")

    # SSDP / UPnP probe
    ssdp = _ssdp_probe(ip)
    if ssdp:
        result["evidence"].append(f"SSDP:{ssdp}")
        # try to infer type
        if "Android" in ssdp or "Android" in (result.get("vendor") or ""):
            result["type"] = "Android Phone"
            result["os"] = result.get("os") or "Android"
        if "iPhone" in ssdp or "Apple" in (result.get("vendor") or ""):
            result["type"] = "iPhone / Mac"
            result["os"] = result.get("os") or "iOS/macOS"

    # banner grab
    banners = _banner_grab(ip)
    if banners:
        result["evidence"].append("BANNER")
        if "Android" in banners or "okhttp" in banners.lower():
            result["type"] = result["type"] or "Android Phone"
            result["os"] = result["os"] or "Android"
        if "iPhone" in banners or "Darwin" in banners:
            result["type"] = result["type"] or "iPhone / Mac"
            result["os"] = result["os"] or "iOS/macOS"
        # sometimes web admin page titles include device model
        m = re.search(r"<title[^>]*>([^<]{2,60})</title>", banners, re.I)
        if m:
            result["model"] = m.group(1).strip()
            result["evidence"].append(f"HTML title:{result['model']}")

    # infer model from vendor string if available
    if result.get("vendor") and not result.get("model"):
        v = result["vendor"].upper()
        if any(x in v for x in ["SAMSUNG", "XIAOMI", "INFINIX", "TECNO", "POCO", "OPPO", "VIVO", "REALME"]):
            result["type"] = result["type"] or "Android Phone"
            result["os"] = result["os"] or "Android"

    result["_ts"] = now
    _IDENTIFY_CACHE[key] = result
    return result
