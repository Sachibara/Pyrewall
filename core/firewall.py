# pyrewall/core/firewall.py
from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB, FIREWALL_LOGS_DB as DB_LOGS
import sqlite3
import socket
import subprocess
import pydivert
import threading
import os

# ensure DB parent directories exist
def _ensure_db_and_abs(path):
    if not path:
        return path
    ab = os.path.abspath(path)
    parent = os.path.dirname(ab)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return ab


def resolve_domain_to_ips(domain: str):
    ips = []
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips

def add_blocked_domain(domain: str):
    _db = _ensure_db_and_abs(DEFAULT_DB)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT UNIQUE)")
        cur.execute("INSERT OR IGNORE INTO blocked_domains (domain) VALUES (?)", (domain,))
        conn.commit()

def remove_blocked_domain(domain: str):
    _db = _ensure_db_and_abs(DEFAULT_DB)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_domains WHERE domain = ?", (domain,))
        conn.commit()

def get_blocked_domains():
    _db = _ensure_db_and_abs(DEFAULT_DB)
    with sqlite3.connect(_db) as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT UNIQUE)")
        cur.execute("SELECT domain FROM blocked_domains")
        rows = cur.fetchall()
    return [r[0] for r in rows]

def add_netsh_block_ip(ip: str, rule_name: str):
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                    "name=" + rule_name, "dir=out", "action=block", "remoteip=" + ip], capture_output=True)

def remove_netsh_block_ip(ip: str, rule_name: str):
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=" + rule_name, "remoteip=" + ip], capture_output=True)

def log_firewall_event(domain: str, action: str):
    _db_logs = _ensure_db_and_abs(DB_LOGS)
    with sqlite3.connect(_db_logs) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS firewall_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                domain TEXT,
                action TEXT
            )
        """)
        cur.execute("INSERT INTO firewall_logs (domain, action) VALUES (?, ?)", (domain, action))
        conn.commit()

def start_windivert_loop(stop_event: threading.Event):
    try:
        domains = get_blocked_domains()
        # capture both directions (so forwarded client traffic is observed) and HTTP/HTTPS/QUIC
        with pydivert.WinDivert(
                "(inbound or outbound) and (tcp.DstPort == 80 or tcp.DstPort == 443 or udp.DstPort == 443)") as w:
            while not stop_event.is_set():
                try:
                    packet = w.recv(timeout=1)
                    payload = bytes(packet.payload or b"")
                    for d in domains:
                        if d.encode() in payload:
                            print(f"[Pyrewall] 🔒 Blocked packet for {d}")
                            log_firewall_event(d, "BLOCKED")
                            break
                    else:
                        w.send(packet)
                except Exception:
                    continue
    except Exception as e:
        print("[firewall] WinDivert loop error:", e)
