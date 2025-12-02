# pyrewall/core/dns_proxy.py
import os
import socket
import threading
import sqlite3
from dnslib import DNSRecord, DNSHeader, RCODE
from pyrewall.db.paths import FIREWALL_DB as DB_PATH_DEFAULT

# pyrewall/core/dns_proxy.py (partial — replace DNSProxy.__init__ only)
class DNSProxy:
    """
    UDP DNS proxy that:
    - Replies NXDOMAIN for blocked domains
    - Forwards other queries to upstream (default 8.8.8.8)
    """
    def __init__(self, bind_addr=("0.0.0.0", 53), upstream=("8.8.8.8", 53), db_path=None):
        self.bind_addr = bind_addr
        self.upstream = upstream
        # use provided db_path or canonical
        from pyrewall.db.paths import FIREWALL_DB as DB_PATH_DEFAULT
        self.db_path = os.path.abspath(db_path or DB_PATH_DEFAULT)
        # ensure parent directory exists in case db_path was custom
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._sock = None
        self._stop = threading.Event()
        self._thread = None
        self._cache = set()
        self._cache_lock = threading.Lock()


    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        print(f"[Pyrewall][DNS] ✅ DNS proxy active at {self.bind_addr[0]}:{self.bind_addr[1]}")

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        print("[Pyrewall][DNS] ⛔ DNS proxy stopped.")

    def refresh_from_db(self):
        """
        Public hook so other modules (firewall thread / UI) can force a DNS
        cache reload after blocked_domains changes.
        """
        self._refresh_cache()


    def _refresh_cache(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=2)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
            cur.execute("SELECT domain FROM blocked_domains")
            domains = [r[0].lower().strip() for r in cur.fetchall() if r and r[0]]
            conn.close()
            with self._cache_lock:
                self._cache = set(domains)
        except Exception as e:
            print(f"[DNSProxy] Cache refresh error: {e}")

    def _is_blocked(self, qname: str):
        qname = qname.rstrip(".").lower()
        with self._cache_lock:
            for d in self._cache:
                if not d:
                    continue
                check = d.lower().lstrip("*.")
                if qname == check or qname.endswith("." + check):
                    return True
        return False

    def _forward_query(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(data, self.upstream)
                reply, _ = s.recvfrom(4096)
                return reply
        except Exception:
            return None

    def _serve(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(self.bind_addr)
        except PermissionError:
            print("[Pyrewall][DNS] ❌ Run as admin to bind UDP port 53.")
            return
        except Exception as e:
            print(f"[Pyrewall][DNS] ❌ Bind error: {e}")
            return

        self._refresh_cache()

        print(f"[Pyrewall][DNS] 🟢 Listening for DNS queries on {self.bind_addr[0]}:{self.bind_addr[1]}")
        while not self._stop.is_set():
            try:
                self._sock.settimeout(1.0)
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle_query, args=(data, addr), daemon=True).start()

    def _handle_query(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")
        except Exception:
            return

        if self._is_blocked(qname):
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=RCODE.NXDOMAIN))
            self._sock.sendto(reply.pack(), addr)
            print(f"[Pyrewall][DNS] 🚫 Blocked: {qname} (client: {addr[0]})")
            return

        reply = self._forward_query(data)
        if reply:
            self._sock.sendto(reply, addr)
