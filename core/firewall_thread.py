# pyrewall/core/firewall_thread.py
import os
import threading
import datetime
import time
import sqlite3
import socket
import struct
import sys
import fnmatch
import subprocess
from pyrewall.db.app_signatures import get_all_signatures
from pyrewall.db.paths import FIREWALL_DB as DEFAULT_DB


try:
    from pyrewall.core.dns_proxy import DNSProxy
except Exception:
    DNSProxy = None

# Try import at module level, but DO NOT raise here.
# We'll import/validate inside the running thread to avoid blocking the UI.
try:
    import pydivert  # may be None if not installed
except Exception:
    pydivert = None


TEMP_BLOCK_TTL_SECONDS = 300
# Signal/event used to instruct the running thread to reload its domain/IP lists immediately.
domain_update_event = threading.Event()


# at top (keep your imports and existing content)...

# ---- add a module-level controller (singleton-like) ----
_firewall_controller = {
    "thread": None,
    "lock": threading.Lock()
}

# --------------------------
# Controller API (singleton)
# --------------------------
import threading as _threading
_controller_lock = _threading.Lock()
_firewall_instance = None

# replace the previous start_firewall(...) in pyrewall/core/firewall_thread.py with this

def start_firewall(db_path=None, filter_str=None):
    """
    Start the firewall thread if not already started.
    This function returns immediately and does minimal work on the caller (UI) thread.
    It spins a short-lived helper thread that constructs the FirewallThread off the UI thread
    and then starts it.
    Returns True if a start was initiated, False otherwise.
    """
    global _firewall_instance

    # quick-check: already running
    with _controller_lock:
        if _firewall_instance and getattr(_firewall_instance, "is_alive", lambda: False)():
            print("[Pyrewall] start_firewall(): already running.")
            return True

    # helper to create the real FirewallThread off the UI thread
    def _starter():
        global _firewall_instance
        with _controller_lock:
            try:
                # Double-check inside lock (race)
                if _firewall_instance and getattr(_firewall_instance, "is_alive", lambda: False)():
                    print("[Pyrewall] start_firewall._starter(): already running.")
                    return True

                # construct FirewallThread (may do costly init) OFF the UI thread
                inst = FirewallThread(db_path=db_path or DEFAULT_DB, filter_str=filter_str)
                inst.daemon = True

                # publish before start to make it visible to stop() if requested
                _firewall_instance = inst

                # now start background thread (run() will handle further heavy work)
                inst.start()
                print("[Pyrewall] start_firewall._starter(): FirewallThread started.")
                return True
            except Exception as e:
                print(f"[Pyrewall] start_firewall._starter() failed: {e}")
                _firewall_instance = None
                return False

    # Double-protect start: don't launch second starter thread
    with _controller_lock:
        if _firewall_instance and getattr(_firewall_instance, "is_alive", lambda: False)():
            print("[Pyrewall] start_firewall(): already running (pre-starter check).")
            return True

    t = threading.Thread(target=_starter, daemon=True)
    t.start()

    # return True because start has been requested (the real thread will start asynchronously)
    print("[Pyrewall] start_firewall(): start requested (starter thread launched).")
    return True



def stop_firewall(wait=True, timeout=8.0):
    """
    Stop the running firewall thread safely.
    Waits up to `timeout` seconds for the thread to exit (checks every 0.1s).
    Returns True if the thread is stopped (or no instance existed), False if still alive after timeout.
    """
    global _firewall_instance
    with _controller_lock:
        if not _firewall_instance:
            print("[Pyrewall] stop_firewall(): no instance.")
            return True

        try:
            # Signal the worker to stop
            try:
                _firewall_instance.stop()
            except Exception as e:
                print(f"[Pyrewall] stop_firewall(): error calling stop(): {e}")

            if not wait:
                # If caller doesn't want to wait, return immediately (the thread will stop asynchronously).
                print("[Pyrewall] stop_firewall(): stop requested (not waiting).")
                return True

            # Poll for thread termination up to timeout seconds (small sleep granularity)
            deadline = time.time() + timeout
            while time.time() < deadline:
                alive = getattr(_firewall_instance, "is_alive", lambda: False)()
                if not alive:
                    break
                # short sleep so we can react quickly without busy-waiting
                time.sleep(0.1)

            alive = getattr(_firewall_instance, "is_alive", lambda: False)()
            if alive:
                print("[Pyrewall] stop_firewall(): thread still alive after join timeout.")
                return False

            # cleaned up successfully
            _firewall_instance = None
            print("[Pyrewall] stop_firewall(): stopped successfully.")
            return True

        except Exception as e:
            print(f"[Pyrewall] stop_firewall() exception: {e}")
            return False



def is_firewall_running():
    """Return True if the firewall worker thread is alive and not stopped."""
    global _firewall_instance
    try:
        if not _firewall_instance:
            return False
        return bool(getattr(_firewall_instance, "is_alive", lambda: False)())
    except Exception:
        return False

def is_firewall_ready():
    """Return True if firewall thread exists and finished heavy init (WinDivert open)."""
    global _firewall_instance
    try:
        if not _firewall_instance:
            return False
        return bool(getattr(_firewall_instance, "_ready", False))
    except Exception:
        return False



def notify_firewall_reload():
    """Call from UI to request the running firewall thread reload lists immediately."""
    domain_update_event.set()

    # Also refresh the DNS proxy cache so NXDOMAIN kicks in right away
    global _firewall_instance
    try:
        if _firewall_instance and getattr(_firewall_instance, "dns_proxy", None):
            try:
                _firewall_instance.dns_proxy.refresh_from_db()
            except AttributeError:
                # older instance or if method name changed
                _firewall_instance.dns_proxy._refresh_cache()
    except Exception as e:
        print(f"[Pyrewall] notify_firewall_reload: DNS cache refresh failed: {e}")



# ----- DB helpers & DNS resolution -----
def resolve_domain_to_ips(domain: str):
    """
    Resolve a domain and its common subdomains to IPv4 addresses.
    Returns a unique set of IPs (for multi-domain / CDN sites).
    """
    import concurrent.futures

    resolved = set()

    def try_resolve(d):
        try:
            infos = socket.getaddrinfo(d, None, family=socket.AF_INET)
            for info in infos:
                resolved.add(info[4][0])
        except Exception:
            pass

    # Common subdomain patterns to attempt
    variants = [
        domain,
        f"www.{domain}",
        f"m.{domain}",
        f"api.{domain}",
        f"cdn.{domain}",
        f"video.{domain}",
        f"static.{domain}",
        f"media.{domain}",
    ]

    # Resolve in parallel for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(try_resolve, variants)

    return list(resolved)


def sync_blocked_ips(db_path=None):
    """
    Resolve all domains in blocked_domains into blocked_ips.
    WinDivert + DNSProxy will enforce blocking.
    Optionally, we *can* mirror into Windows Firewall, but that is disabled by default.
    """
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    ensure_blocked_ips_schema(db_path)

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips(ip TEXT PRIMARY KEY)")

        cur.execute("DELETE FROM blocked_ips")
        cur.execute("SELECT domain FROM blocked_domains")
        domains = [r[0] for r in cur.fetchall()]

        all_ips = set()
        for d in domains:
            for ip in resolve_domain_to_ips(d):
                all_ips.add(ip)

        for ip in all_ips:
            cur.execute("INSERT OR IGNORE INTO blocked_ips(ip) VALUES (?)", (ip,))

        conn.commit()
        conn.close()

        print(f"[Pyrewall] Synced {len(all_ips)} blocked IPs from {len(domains)} domains.")

    except Exception as e:
        print(f"[Pyrewall] sync_blocked_ips() error: {e}")


    except Exception as e:
        print(f"[Pyrewall] sync_blocked_ips() error: {e}")

def reload_blocked_domains(db_path=None):
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    """Return list of blocked domains (lowercase)."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
        cur.execute("SELECT domain FROM blocked_domains")
        domains = [row[0].lower() for row in cur.fetchall()]
        conn.close()
        return domains
    except Exception as e:
        print(f"[Pyrewall] reload_blocked_domains() error: {e}")
        return []

def ensure_blocked_ips_schema(db_path=None):
    """
    Ensure blocked_ips table exists and has the expected columns:
      - ip TEXT PRIMARY KEY
      - domain TEXT
      - expires_at DATETIME
      - reason TEXT

    This migration is idempotent and safe: it will create the table if missing
    and add missing columns using ALTER TABLE ADD COLUMN (supported by SQLite).
    """
    db_path = db_path or DEFAULT_DB
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        # Ensure base table exists (minimal)
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY)")
        # Inspect existing columns
        cur.execute("PRAGMA table_info(blocked_ips)")
        existing = {row[1] for row in cur.fetchall()}  # set of column names
        # Desired extra columns
        extras = {
            "domain": "TEXT",
            "expires_at": "DATETIME",
            "reason": "TEXT"
        }
        for col, coltype in extras.items():
            if col not in existing:
                try:
                    cur.execute(f"ALTER TABLE blocked_ips ADD COLUMN {col} {coltype}")
                except Exception as e:
                    # Log but continue; this is best-effort migration
                    print(f"[Pyrewall] ensure_blocked_ips_schema: failed to add column {col}: {e}")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Pyrewall] ensure_blocked_ips_schema error: {e}")


def get_blocked_ips(db_path=None):
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    """Return set of blocked IP strings."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips(ip TEXT UNIQUE)")
        cur.execute("SELECT ip FROM blocked_ips")
        ips = {row[0] for row in cur.fetchall()}
        conn.close()
        return ips
    except Exception as e:
        print(f"[Pyrewall] get_blocked_ips() error: {e}")
        return set()


def add_blocked_domain(domain: str, db_path=None):
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    """Add domain to blocked_domains table (lowercased) and immediately sync its IPs."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
        cur.execute("INSERT OR IGNORE INTO blocked_domains(domain) VALUES (?)", (domain.lower(),))
        conn.commit()
        conn.close()
        print(f"[Pyrewall] Added blocked domain: {domain}")
        # Immediately resolve and populate blocked_ips so blocking takes effect right away
        try:
            sync_blocked_ips(db_path=db_path)
            # If the worker thread is running, signal reload so in-memory lists update quickly
            domain_update_event.set()
        except Exception as e:
            print(f"[Pyrewall] Warning: sync_blocked_ips() failed after adding domain: {e}")
    except Exception as e:
        print(f"[Pyrewall] add_blocked_domain() error: {e}")



def remove_blocked_domain(domain: str, db_path=None):
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    """Remove domain from blocked_domains table and resync IPs."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_domains WHERE domain = ?", (domain.lower(),))
        conn.commit()
        conn.close()
        print(f"[Pyrewall] Removed blocked domain: {domain}")
        # Re-sync IPs so WinDivert stops blocking them
        try:
            sync_blocked_ips(db_path=db_path)
            domain_update_event.set()
        except Exception as e:
            print(f"[Pyrewall] Warning: sync_blocked_ips() failed after removing domain: {e}")
    except Exception as e:
        print(f"[Pyrewall] remove_blocked_domain() error: {e}")



# ----- Packet parsing helpers -----
def extract_http_host(payload: bytes):
    """Return Host header value for HTTP request payload, or None."""
    try:
        if not payload:
            return None
        # only try for plausible HTTP requests
        if not (payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HEAD ")
                or payload.startswith(b"PUT ") or payload.startswith(b"OPTIONS ")):
            return None
        text = payload.decode("iso-8859-1", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                return host.split(":")[0].lower()
    except Exception:
        pass
    return None


def extract_tls_sni(payload: bytes):
    """Extract SNI from TLS ClientHello (best-effort)."""
    try:
        if len(payload) < 5:
            return None
        # TLS record header: ContentType(1)=0x16 Handshake
        if payload[0] != 0x16:
            return None
        # ensure handshake present
        if len(payload) < 6 or payload[5] != 0x01:
            return None
        offset = 5 + 4  # record + handshake header
        if len(payload) < offset + 34:
            return None
        offset += 34
        # session id
        if len(payload) < offset + 1:
            return None
        sid_len = payload[offset]
        offset += 1 + sid_len
        if len(payload) < offset + 2:
            return None
        cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cs_len
        if len(payload) < offset + 1:
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        if len(payload) < offset + 2:
            return None
        ext_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        end_ext = offset + ext_len
        if end_ext > len(payload):
            return None
        while offset + 4 <= end_ext:
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_size = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0x0000:  # SNI
                if offset + 2 > end_ext:
                    return None
                sn_list_len = struct.unpack("!H", payload[offset:offset + 2])[0]
                offset += 2
                sn_end = offset + sn_list_len
                while offset + 3 <= sn_end:
                    name_type = payload[offset]
                    name_len = struct.unpack("!H", payload[offset + 1:offset + 3])[0]
                    offset += 3
                    if offset + name_len > sn_end:
                        return None
                    if name_type == 0:
                        server_name = payload[offset:offset + name_len].decode("utf-8", errors="ignore")
                        return server_name.split(":")[0].lower()
                    offset += name_len
                return None
            else:
                offset += ext_size
        return None
    except Exception:
        return None


# Common DoH host fragments to look for in payloads (basic)
DOH_HOST_FRAGMENTS = [b"dns.google", b"cloudflare-dns.com", b"mozilla.cloudflare-dns.com", b"one.one.one.one"]


# ----- Firewall thread itself -----
class FirewallThread(threading.Thread):
    def __init__(self, db_path=None, filter_str=None):
        super().__init__(daemon=True)
        self.db_path = db_path or DEFAULT_DB

        # capture forwarded HTTP/HTTPS/QUIC for both directions
        self.filter_str = filter_str or (
            "(inbound or outbound) and "
            "(tcp.DstPort == 80 or tcp.DstPort == 443 or udp.DstPort == 443)"
        )
        self._stop_event = threading.Event()
        self._ready = False  # indicates thread fully started (WinDivert opened)

        # Core runtime state
        self.domains = []
        self.blocked_ips = set()
        # Load user-defined app signatures (dynamic blocking rules)
        self.app_signatures = get_all_signatures()
        print(f"[Pyrewall] 🔁 Loaded {len(self.app_signatures)} app signatures.")
        self._last_reload = 0
        self._failure_count = 0
        self._last_printed_failure = 0
        self._failure_backoff = 0.05
        # blocked packet aggregation (reduce log spam)
        # { ip_str: count_since_last_flush }
        self._blocked_counters = {}
        self._last_blocked_flush = 0.0
        self._blocked_flush_interval = 1.0  # seconds


        # ---------- TEMP BLOCK / CRITICAL IPS ----------
        # TTL for temporary auto-blocked IPs (seconds)
        self.TEMP_BLOCK_TTL_SECONDS = 300  # 5 minutes

        # critical IPs we must never auto-block (gateway, DNS, loopback)
        self._critical_ips = set(["127.0.0.1", "0.0.0.0", "localhost"])
        try:
            # optional detection of local gateway (requires netifaces)
            import netifaces
            gw = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
            if gw:
                self._critical_ips.add(gw[0])
        except Exception:
            # netifaces may not be installed — that's ok
            pass

        # always protect common public resolvers (prevent cutting your DNS)
        for _dns in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"):
            self._critical_ips.add(_dns)

        # small in-memory map to track temporary IP insertion times (fast checks)
        # { ip_str: expires_epoch }
        self._temp_block_expiry = {}
        # -------------------------------------------------

        # optional DNS proxy instance (non-blocking start expected)
        if DNSProxy is not None:
            try:
                self.dns_proxy = DNSProxy(bind_addr=("0.0.0.0", 53),
                                          upstream=("8.8.8.8", 53),
                                          db_path=self.db_path)
            except Exception as e:
                print(f"[Pyrewall] DNSProxy init failed: {e}")
                self.dns_proxy = None
        else:
            self.dns_proxy = None

    def stop(self):
        self._stop_event.set()
        try:
            if getattr(self, "_w", None):
                # best-effort: close WinDivert so recv() unblocks
                try:
                    self._w.close()
                except Exception:
                    pass
        except Exception:
            pass

    def _reload_lists(self):
        try:
            self.domains = reload_blocked_domains(self.db_path)
            self.blocked_ips = get_blocked_ips(self.db_path)
            print(f"[Pyrewall] Reloaded {len(self.domains)} domains and {len(self.blocked_ips)} IPs.")
        except Exception as e:
            print("[Pyrewall] reload lists error:", e)

    def _resolve_and_store_ips(self, domain_hit):
        """Resolve domain and store IPs into blocked_ips table (atomic)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS blocked_ips(ip TEXT UNIQUE)")
            resolved = []
            for info in socket.getaddrinfo(domain_hit, None, family=socket.AF_INET):
                ip = info[4][0]
                cur.execute("INSERT OR IGNORE INTO blocked_ips(ip) VALUES (?)", (ip,))
                resolved.append(ip)
            conn.commit()
            conn.close()
            if resolved:
                print(f"[AUTO-BLOCK] Added {len(resolved)} IP(s) for {domain_hit}: {', '.join(resolved)}")
                # update in-memory quickly
                self.blocked_ips = get_blocked_ips(self.db_path)
        except Exception as e:
            print(f"[AUTO-BLOCK] DNS resolve/store failed for {domain_hit}: {e}")

    def _add_temporary_block_ip(self, ip: str, domain_hit: str, ttl_seconds: int = TEMP_BLOCK_TTL_SECONDS):
        """Add a specific IP to blocked_ips temporarily (safe)."""
        try:
            if not ip:
                return
            # never block critical IPs
            if ip in self._critical_ips:
                return

            # ensure schema exists
            ensure_blocked_ips_schema(self.db_path)

            expires_at = (datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl_seconds)).strftime(
                "%Y-%m-%d %H:%M:%S")
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            # now the table is guaranteed (or best-effort) to have domain/expires_at/reason columns
            cur.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, domain, expires_at, reason) VALUES (?, ?, ?, ?)",
                (ip, domain_hit, expires_at, "auto-temp"))
            conn.commit()
            conn.close()
            # refresh in-memory list
            self.blocked_ips = get_blocked_ips(self.db_path)
        except Exception as e:
            print(f"[Pyrewall] _add_temporary_block_ip error: {e}")

    def _cleanup_expired_blocked_ips(self):
        """Remove expired temporary IP entries from DB periodically."""
        try:
            ensure_blocked_ips_schema(self.db_path)
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            # If column exists, delete expired; otherwise nothing to do.
            cur.execute("PRAGMA table_info(blocked_ips)")
            cols = {row[1] for row in cur.fetchall()}
            if "expires_at" in cols:
                now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
                conn.commit()
            conn.close()
            self.blocked_ips = get_blocked_ips(self.db_path)
        except Exception as e:
            print(f"[Pyrewall] cleanup_expired_blocked_ips error: {e}")

    def run(self):
        print("[Pyrewall] ✅ WinDivert thread starting...")

        # If pydivert is not available, exit cleanly (no crash on machines without it)
        if pydivert is None:
            print("[Pyrewall] ❌ pydivert is not installed. Firewall packet capture is disabled.")
            return

        # start DNS proxy (if available)
        if self.dns_proxy:
            try:
                self.dns_proxy.start()
                print("[Pyrewall] [DNS] ✅ DNS proxy started.")
            except Exception as e:
                print(f"[Pyrewall] [DNS] failed to start: {e}")

        time.sleep(0.2)

        dll_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "dll"))
        if dll_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + dll_dir

        dll_path = os.path.join(dll_dir, "WinDivert.dll")
        sys_path = os.path.join(dll_dir, "WinDivert64.sys")

        if not os.path.exists(dll_path) or not os.path.exists(sys_path):
            print("[Pyrewall] ❌ WinDivert files missing.")
            return

        # ensure schema for blocked_ips exists before we read it
        ensure_blocked_ips_schema(self.db_path)

        # initial load
        self.domains = reload_blocked_domains(self.db_path)
        self.blocked_ips = get_blocked_ips(self.db_path)
        self._last_reload = time.time()
        print(f"[Pyrewall] 🔁 Loaded {len(self.domains)} domains and {len(self.blocked_ips)} IPs.")

        try:
            with pydivert.WinDivert(self.filter_str) as w:
                self._w = w
                # Mark the worker thread as fully active/ready so the UI can stop polling.
                self._ready = True
                print("[Pyrewall] ✅ WinDivert opened successfully — capturing outbound TCP/UDP packets...")
                print("[Pyrewall] 🔥 Firewall is now fully active and capturing.")

                while not self._stop_event.is_set():
                    # immediate reload if UI requested or periodic
                    if domain_update_event.is_set() or time.time() - self._last_reload > 3:
                        self._reload_lists()
                        self._last_reload = time.time()
                        domain_update_event.clear()

                    # periodic cleanup expired temp IP entries every minute
                    if time.time() - getattr(self, "_last_blocked_ips_cleanup", 0) > 60:
                        try:
                            self._cleanup_expired_blocked_ips()
                        except Exception:
                            pass
                        self._last_blocked_ips_cleanup = time.time()

                    # Periodically reload app signatures every 60 seconds
                    if time.time() - getattr(self, "_last_app_reload", 0) > 60:
                        try:
                            from pyrewall.db.app_signatures import get_all_signatures
                            self.app_signatures = get_all_signatures()
                            print(f"[Pyrewall] 🔁 Reloaded {len(self.app_signatures)} app signatures.")
                        except Exception as e:
                            print(f"[Pyrewall] ⚠️ Failed to reload app signatures: {e}")
                        self._last_app_reload = time.time()

                    # Periodically resolve IPs for all blocked domains every 5 minutes
                    if time.time() - getattr(self, "_last_domain_ip_resolve", 0) > 300:
                        for d in self.domains:
                            try:
                                new_ips = resolve_domain_to_ips(d)
                                if new_ips:
                                    for ip in new_ips:
                                        # Store each IP temporarily for this domain
                                        self._add_temporary_block_ip(ip, d, ttl_seconds=self.TEMP_BLOCK_TTL_SECONDS)
                                    print(f"[Pyrewall] 🌐 Resolved and added {len(new_ips)} IPs for {d}")
                            except Exception as e:
                                print(f"[Pyrewall] ⚠️ Failed to resolve IPs for {d}: {e}")
                        self._last_domain_ip_resolve = time.time()

                    try:
                        # recv with optional timeout support for pydivert versions
                        try:
                            pkt = w.recv(timeout=500)
                        except TypeError:
                            pkt = w.recv()
                        if not pkt:
                            continue

                        # get dst ip/port/protocol robustly
                        dst_ip = str(getattr(pkt, "dst_addr", "") or "")
                        dst_port = getattr(pkt, "dst_port", None)
                        protocol = getattr(pkt, "protocol", None)

                        # 1) fast IP-level block
                        if dst_ip and dst_ip in self.blocked_ips:
                            # aggregate blocked counts per IP to avoid log spam
                            try:
                                self._blocked_counters[dst_ip] = self._blocked_counters.get(dst_ip, 0) + 1
                            except Exception:
                                # fallback to direct print if aggregation fails
                                print(f"[BLOCKED] Dropped packet to blocked IP: {dst_ip}")

                            # flush counts periodically (safe access)
                            now = time.time()
                            if now - getattr(self, "_last_blocked_flush", 0.0) >= getattr(self,
                                                                                          "_blocked_flush_interval",
                                                                                          1.0):
                                try:
                                    for ip, cnt in list(self._blocked_counters.items()):
                                        print(f"[BLOCKED] Dropped {cnt} packet(s) to blocked IP: {ip}")
                                    self._blocked_counters.clear()
                                except Exception:
                                    pass
                                self._last_blocked_flush = now

                            continue

                        # 2) block QUIC (UDP/443) universally to prevent HTTP/3 bypass
                        if protocol is not None:
                            try:
                                is_udp = (protocol == pydivert.Protocol.UDP)
                            except Exception:
                                # fallback when Protocol enum differs
                                is_udp = (str(protocol).lower().find("udp") >= 0)
                        else:
                            is_udp = False

                        if is_udp and dst_port == 443:
                            # drop QUIC traffic (prevents many bypasses)
                            print(f"[BLOCKED] Dropped UDP/443 (QUIC) packet to {dst_ip}")
                            continue

                        # 3) inspect payload for HTTP Host or TLS SNI
                        payload = bytes(pkt.payload or b"")
                        host = extract_http_host(payload) or extract_tls_sni(payload)
                        domain_hit = None
                        # DEBUG: show all HTTP/TLS hosts we see
                        if host:
                            print(f"[DEBUG] HTTP/TLS host: {host} → {dst_ip}")


                        if host:
                            for d in self.domains:
                                if host == d or host.endswith("." + d):
                                    domain_hit = d
                                    break

                        # 4) fallback payload scan (brute-force substring)
                        if not domain_hit:
                            low_payload = payload.lower()
                            for d in self.domains:
                                if d.encode() in low_payload:
                                    domain_hit = d
                                    break

                        # 5) block DoH quick fragments (prevent DNS-over-HTTPS quick bypass)
                        if any(fragment in payload.lower() for fragment in DOH_HOST_FRAGMENTS):
                            print("[BLOCKED] Dropped DoH-like packet (payload contained known DoH host fragment).")
                            continue

                        if domain_hit:
                            detection_type = "host" if host else "payload-substring"
                            print(
                                f"[AUTO] Detected packet to blocked domain: {domain_hit} (detection={detection_type}, host={host})")
                            # Add a temporary IP block only for the specific destination IP observed
                            if dst_ip:
                                try:
                                    self._add_temporary_block_ip(dst_ip, domain_hit)
                                except Exception as e:
                                    print(f"[AUTO] temp block error: {e}")
                            # drop current packet
                            print(f"[BLOCKED] Dropped packet to blocked domain {domain_hit}")
                            continue

                        # --- App-level Blocking (user-defined patterns) ---
                        app_match = None
                        if host:
                            for _, app_name, pattern, ip_range, proto in self.app_signatures:
                                if pattern and fnmatch.fnmatch(host, pattern):
                                    app_match = (app_name, pattern)
                                    break

                        if app_match:
                            app_name, pattern = app_match
                            print(f"[APPBLOCK] Dropping packet for app '{app_name}' (host={host})")

                            # Optional: temporarily block the destination IP as well, for efficiency
                            if dst_ip:
                                try:
                                    self._add_temporary_block_ip(dst_ip, pattern)
                                except Exception as e:
                                    print(f"[APPBLOCK] temp IP block failed: {e}")

                            # Drop this packet
                            continue

                        # not blocked -> reinject
                        try:
                            w.send(pkt)

                        except Exception as send_exc:
                            # reinject failure handling with light backoff
                            self._failure_count += 1
                            self._failure_backoff = min(1.0,
                                                        self._failure_backoff * 1.3 if self._failure_count > 1 else 0.05)
                            if self._failure_count - self._last_printed_failure >= 50:
                                print(f"[Pyrewall] ⚠️ reinject send() unexpected error (suppressed): {send_exc}")
                                self._last_printed_failure = self._failure_count
                            time.sleep(self._failure_backoff)

                    except Exception as perr:
                        # Certain WinDivert/Windows errors are expected on shutdown (handle closed).
                        # Detect Win32 I/O-aborted (WinError 995), invalid handle (WinError 6),
                        # or textual hints and exit quietly.
                        try:
                            win_err = getattr(perr, "winerror", None)
                            msg = str(perr).lower()
                            if win_err in (995, 6) or \
                                    "handle is not open" in msg or \
                                    "handle is invalid" in msg or \
                                    "aborted" in msg:
                                # expected during shutdown -> break out and let finally handle cleanup
                                print(f"[Pyrewall] Packet processing aborted (likely shutdown).")
                                break
                        except Exception:
                            # if something goes wrong inspecting the error, fall through to normal reporting
                            pass

                        # For other unexpected errors, print once and continue with light backoff
                        print(f"[Pyrewall] Packet processing error: {perr}")
                        time.sleep(0.01)

        except Exception as e:
            msg = str(e).lower()
            win_err = getattr(e, "winerror", None)

            # Ignore normal shutdown errors
            if win_err in (6, 995) or "handle is invalid" in msg or "aborted" in msg:
                # expected at shutdown
                pass
            else:
                print(f"[Pyrewall] WinDivert open error: {e}")

        finally:
            # ensure ready flag is cleared before stopping
            try:
                self._ready = False
            except Exception:
                pass

            # flush blocked counters once on shutdown so we don't lose counts
            try:
                for ip, cnt in list(getattr(self, "_blocked_counters", {}).items()):
                    print(f"[BLOCKED] Dropped {cnt} packet(s) to blocked IP: {ip}")
            except Exception:
                pass

            if self.dns_proxy:
                try:
                    self.dns_proxy.stop()
                    print("[Pyrewall] [DNS] ⛔ DNS proxy stopped.")
                except Exception:
                    pass

            print("[Pyrewall] Firewall thread stopping gracefully.")
            print("[Pyrewall] Thread closed.")
