# pyrewall/core/devices.py
import os
from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB
import subprocess
import re
import sqlite3
from datetime import datetime

def detect_devices():
    """Return list of (IP, MAC) from ARP table for hosted network."""
    try:
        output = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")
        pattern = re.compile(r"(192\.168\.\d+\.\d+)\s+([\da-fA-F:-]+)")
        devices = pattern.findall(output)
        return devices
    except Exception as e:
        print("[devices] detect error:", e)
        return []

def add_blocked_device(ip: str):
    """Block a device using its MAC address via ARP and firewall."""
    mac = _get_mac(ip)
    if mac == "Unknown":
        print(f"[devices] ⚠️ Cannot find MAC for {ip}, skipping block.")
        return

    _db = os.path.abspath(DEFAULT_DB)
    os.makedirs(os.path.dirname(_db), exist_ok=True)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_devices (ip TEXT UNIQUE, mac TEXT, date_blocked TEXT)")
        cur.execute("INSERT OR IGNORE INTO blocked_devices (ip, mac, date_blocked) VALUES (?, ?, ?)",
                    (ip, mac, datetime.now().isoformat()))
        conn.commit()

    # 🧱 Add static invalid ARP entry (drop traffic)
    subprocess.run(["arp", "-s", ip, "00-00-00-00-00-00"], capture_output=True)

    # 🧱 Add firewall rule (in + out)
    for direction in ["in", "out"]:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Pyrewall_Block_{ip}_{direction}", f"dir={direction}",
            "action=block", f"remoteip={ip}"
        ], capture_output=True, text=True)

    print(f"[devices] ⛔ Blocked {ip} ({mac})")

def remove_blocked_device(ip: str):
    """Unblock a device safely without restarting ICS."""
    _db = os.path.abspath(DEFAULT_DB)
    os.makedirs(os.path.dirname(_db), exist_ok=True)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_devices WHERE ip=?", (ip,))
        conn.commit()

    # Remove ARP static entry
    subprocess.run(["arp", "-d", ip], capture_output=True)

    # Remove both firewall rules (in + out)
    for direction in ["in", "out"]:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Pyrewall_Block_{ip}_{direction}"
        ], capture_output=True, text=True)

    print(f"[devices] ✅ Unblocked {ip}")

def get_blocked_devices():
    """Return blocked IPs + MACs from DB."""
    _db = os.path.abspath(DEFAULT_DB)
    os.makedirs(os.path.dirname(_db), exist_ok=True)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_devices (ip TEXT UNIQUE, mac TEXT, date_blocked TEXT)")
        cur.execute("SELECT ip, mac FROM blocked_devices")
        return cur.fetchall()

def _get_mac(ip: str):
    """Try to resolve MAC address for given IP from ARP cache (best-effort)."""
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        for line in output.splitlines():
            if ip in line:
                m = re.search(r"([0-9A-Fa-f:-]{17}|[0-9A-Fa-f:-]{14}|[0-9A-Fa-f]{12})", line)
                if m:
                    mac = m.group(0)
                    mac = mac.replace("-", ":").upper()
                    if len(mac) == 12:
                        mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
                    return mac
        return "Unknown"
    except Exception:
        return "Unknown"
