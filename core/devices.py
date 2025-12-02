# pyrewall/core/devices.py
import os
from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB
import subprocess
import re
import sqlite3
from datetime import datetime

def _ensure_blocked_devices_schema(db_path: str | None = None):
    """
    Ensure blocked_devices table exists and has:
      - ip TEXT UNIQUE
      - mac TEXT
      - date_blocked TEXT (optional timestamp)
    Safe and idempotent.
    """
    _db = os.path.abspath(db_path or DEFAULT_DB)
    os.makedirs(os.path.dirname(_db), exist_ok=True)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        # Create minimal table if missing
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_devices (ip TEXT UNIQUE, mac TEXT)")
        # Inspect existing columns
        cur.execute("PRAGMA table_info(blocked_devices)")
        cols = {row[1] for row in cur.fetchall()}
        if "date_blocked" not in cols:
            cur.execute("ALTER TABLE blocked_devices ADD COLUMN date_blocked TEXT")
        conn.commit()

def detect_devices():
    """Return list of (IP, MAC) from ARP table (IPv4-only, best-effort)."""
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        # Match ANY IPv4 address and corresponding MAC-like field
        pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F:-]+)")
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
    _ensure_blocked_devices_schema(_db)

    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO blocked_devices (ip, mac, date_blocked) VALUES (?, ?, ?)",
            (ip, mac, datetime.now().isoformat())
        )
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
    _ensure_blocked_devices_schema(_db)

    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_devices WHERE ip=?", (ip,))
        conn.commit()

    subprocess.run(["arp", "-d", ip], capture_output=True)

    for direction in ["in", "out"]:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Pyrewall_Block_{ip}_{direction}"
        ], capture_output=True, text=True)

    print(f"[devices] ✅ Unblocked {ip}")


def get_blocked_devices():
    """Return blocked IPs + MACs from DB."""
    _db = os.path.abspath(DEFAULT_DB)
    _ensure_blocked_devices_schema(_db)

    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
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
