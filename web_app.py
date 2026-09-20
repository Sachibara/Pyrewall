from __future__ import annotations

import argparse
import ctypes
import importlib.util
import ipaddress
import json
import logging
import os
import platform
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent

# Make the repository importable as "pyrewall" even when the checkout folder is
# named "Pyrewall" on a case-sensitive filesystem.
if "pyrewall" not in sys.modules:
    init_file = ROOT / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "pyrewall",
        init_file,
        submodule_search_locations=[str(ROOT)],
    )
    if spec and spec.loader:
        package = importlib.util.module_from_spec(spec)
        sys.modules["pyrewall"] = package
        spec.loader.exec_module(package)

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from pyrewall.core.devices import (
    add_blocked_device,
    detect_devices,
    get_blocked_devices,
    remove_blocked_device,
)
from pyrewall.core.firewall_thread import (
    add_blocked_domain,
    ensure_blocked_ips_schema,
    get_blocked_ips,
    is_firewall_ready,
    is_firewall_running,
    notify_firewall_reload,
    remove_blocked_domain,
    start_firewall,
    stop_firewall,
)
from pyrewall.core.security import (
    create_user,
    ensure_default_admin,
    is_admin,
    set_password,
    validate_user,
)
from pyrewall.db.app_signatures import (
    add_signature,
    get_all_signatures,
    init_app_signatures,
    remove_signature,
)
from pyrewall.db.paths import (
    BASE_DIR,
    FIREWALL_DB,
    FIREWALL_LOGS_DB,
    GENERAL_HISTORY_DB,
    USERS_DB,
)
from pyrewall.db.storage import log_general_history

try:
    import psutil
except Exception:
    psutil = None

WEB_DIR = ROOT / "web"
SETTINGS_DIR = Path(BASE_DIR) / "config"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"
THREATS_DB = Path(BASE_DIR) / "threats.db"
BACKUP_DIR = Path(BASE_DIR) / "backups" / "web"
DEFAULT_SETTINGS = {
    "auto_start": False,
    "detailed_logging": False,
    "dark_mode": True,
    "dns_proxy_enabled": True,
    "create_netsh_blocks": True,
}

app = Flask(
    __name__,
    template_folder=str(WEB_DIR / "templates"),
    static_folder=str(WEB_DIR / "static"),
)
app.config.update(
    SECRET_KEY=os.environ.get("PYREWALL_WEB_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=1024 * 1024,
)

_traffic_lock = threading.Lock()
_traffic_state = {"ts": time.time(), "sent": 0, "recv": 0}


def db(path):
    conn = sqlite3.connect(os.path.abspath(str(path)), timeout=8)
    conn.row_factory = sqlite3.Row
    return conn


def init_web_schema():
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ensure_default_admin()
    init_app_signatures(FIREWALL_DB)
    ensure_blocked_ips_schema(FIREWALL_DB)

    with db(FIREWALL_DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS blocked_domains(domain TEXT UNIQUE)")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS blocked_devices(
                ip TEXT UNIQUE,
                mac TEXT,
                date_blocked TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS firewall_rules(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip TEXT,
                port TEXT,
                protocol TEXT,
                action TEXT
            )"""
        )

    with db(GENERAL_HISTORY_DB) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS history(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS archived_history(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                orig_id INTEGER,
                username TEXT,
                action TEXT,
                description TEXT,
                timestamp DATETIME,
                archived_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )

    with db(THREATS_DB) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS threats(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                severity TEXT,
                description TEXT
            )"""
        )


def load_settings():
    settings = DEFAULT_SETTINGS.copy()
    try:
        if SETTINGS_FILE.exists():
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                settings.update({k: loaded[k] for k in DEFAULT_SETTINGS if k in loaded})
    except Exception:
        pass
    return settings


def save_settings_file(settings):
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def apply_runtime_settings(settings):
    level = logging.DEBUG if settings.get("detailed_logging") else logging.INFO
    for name in ("pyrewall.system", "pyrewall.firewall", "pyrewall.alert"):
        logging.getLogger(name).setLevel(level)


def startup_script_path():
    if os.name != "nt":
        return None
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    path = (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "pyrewall_web_startup.bat"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def set_autostart(enabled):
    path = startup_script_path()
    if path is None:
        return False, "Auto-start is only supported on Windows."
    if enabled:
        command = f'@echo off\ncd /d "{ROOT}"\n"{sys.executable}" "{ROOT / "web_app.py"}"\n'
        path.write_text(command, encoding="utf-8")
        return True, "Web firewall auto-start enabled."
    try:
        if path.exists():
            path.unlink()
        return True, "Web firewall auto-start disabled."
    except Exception as exc:
        return False, str(exc)


def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def current_user():
    return session.get("username")


def current_role():
    return session.get("role", "user")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "authentication_required"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapped


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if current_role() != "admin":
            return jsonify({"ok": False, "error": "admin_required"}), 403
        return fn(*args, **kwargs)

    return wrapped


@app.before_request
def protect_mutations():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.endpoint == "login":
            expected = session.get("_csrf")
            received = request.form.get("_csrf")
        elif request.path.startswith("/api/"):
            expected = session.get("_csrf")
            received = request.headers.get("X-CSRF-Token")
        else:
            return None
        if not expected or not received or not secrets.compare_digest(expected, received):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "csrf_failed"}), 403
            return "Invalid CSRF token", 403
    return None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def ok(**kwargs):
    return jsonify({"ok": True, **kwargs})


def fail(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def normalize_domain(value):
    value = str(value or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    host = urlsplit(value).hostname or ""
    host = host.strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or " " in host or "." not in host:
        return ""
    return host


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def process_is_admin():
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def count_rows(path, table):
    try:
        with db(path) as conn:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            return int(row["n"]) if row else 0
    except Exception:
        return 0


def overview_data():
    return {
        "firewall": {
            "running": bool(is_firewall_running()),
            "ready": bool(is_firewall_ready()),
            "administrator": process_is_admin(),
            "platform": platform.platform(),
            "hostname": socket.gethostname(),
        },
        "counts": {
            "domains": count_rows(FIREWALL_DB, "blocked_domains"),
            "blocked_ips": count_rows(FIREWALL_DB, "blocked_ips"),
            "devices": count_rows(FIREWALL_DB, "blocked_devices"),
            "rules": count_rows(FIREWALL_DB, "firewall_rules"),
            "signatures": count_rows(FIREWALL_DB, "app_signatures"),
            "threats": count_rows(THREATS_DB, "threats"),
            "users": count_rows(USERS_DB, "users"),
        },
    }


def traffic_sample():
    if psutil is None:
        return {"available": False, "sent_bps": 0, "recv_bps": 0, "total_sent": 0, "total_recv": 0}
    counters = psutil.net_io_counters()
    now = time.time()
    with _traffic_lock:
        previous = dict(_traffic_state)
        dt = max(0.2, now - previous["ts"])
        sent_bps = max(0, counters.bytes_sent - previous["sent"]) / dt
        recv_bps = max(0, counters.bytes_recv - previous["recv"]) / dt
        _traffic_state.update({"ts": now, "sent": counters.bytes_sent, "recv": counters.bytes_recv})
    return {
        "available": True,
        "sent_bps": round(sent_bps, 2),
        "recv_bps": round(recv_bps, 2),
        "total_sent": counters.bytes_sent,
        "total_recv": counters.bytes_recv,
    }


def apply_netsh_rule(rule_id, ip, port, protocol, action):
    if os.name != "nt":
        return False, "Saved to database; Windows netsh enforcement is unavailable on this OS."

    action_arg = "block" if action == "BLOCK" else "allow"
    proto_arg = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMPv4", "ANY": "ANY"}[protocol]
    errors = []

    for direction in ("in", "out"):
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Pyrewall_WebRule_{rule_id}_{direction}",
            f"dir={direction}",
            f"action={action_arg}",
            f"remoteip={ip}",
            f"protocol={proto_arg}",
        ]
        if port != "ANY" and protocol in {"TCP", "UDP"}:
            cmd.append(f"remoteport={port}")
        completed = __import__("subprocess").run(cmd, capture_output=True, text=True)
        if completed.returncode != 0:
            errors.append(completed.stderr.strip() or completed.stdout.strip())

    return (not errors), ("; ".join(errors) if errors else "Rule applied to Windows Firewall.")


def delete_netsh_rule(rule_id):
    if os.name != "nt":
        return
    subprocess = __import__("subprocess")
    for direction in ("in", "out"):
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=Pyrewall_WebRule_{rule_id}_{direction}",
            ],
            capture_output=True,
            text=True,
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    csrf_token()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username and password and validate_user(username, password):
            session.clear()
            session["username"] = username
            session["role"] = "admin" if is_admin(username) else "user"
            csrf_token()
            log_general_history(username, "Login Success", f"Web login ({session['role']})")
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
        log_general_history(username or "(blank)", "Login Failed", "Web login attempt failed.")
    return render_template("login.html", csrf=csrf_token(), error=error)


@app.get("/logout")
def logout():
    username = current_user()
    if username:
        log_general_history(username, "Logout", "Web session ended")
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=current_user(),
        role=current_role(),
        csrf=csrf_token(),
    )


@app.get("/api/bootstrap")
@login_required
def api_bootstrap():
    return ok(
        username=current_user(),
        role=current_role(),
        csrf=csrf_token(),
        overview=overview_data(),
        settings=load_settings(),
    )


@app.get("/api/overview")
@login_required
def api_overview():
    return ok(overview=overview_data())


@app.get("/api/traffic")
@login_required
def api_traffic():
    return ok(traffic=traffic_sample())


@app.post("/api/firewall/start")
@admin_required
def api_firewall_start():
    if not process_is_admin():
        return fail("PyreWall must be run with administrator privileges to activate WinDivert.", 409)
    initiated = bool(start_firewall(db_path=FIREWALL_DB))
    log_general_history(current_user(), "Start Firewall", "Start requested from web dashboard")
    return ok(initiated=initiated, running=is_firewall_running(), ready=is_firewall_ready())


@app.post("/api/firewall/stop")
@admin_required
def api_firewall_stop():
    stopped = bool(stop_firewall(wait=True, timeout=8.0))
    log_general_history(current_user(), "Stop Firewall", "Stop requested from web dashboard")
    return ok(stopped=stopped, running=is_firewall_running(), ready=is_firewall_ready())


@app.get("/api/domains")
@login_required
def api_domains():
    with db(FIREWALL_DB) as conn:
        rows = conn.execute("SELECT domain FROM blocked_domains ORDER BY domain").fetchall()
    return ok(domains=[row["domain"] for row in rows])


@app.post("/api/domains")
@admin_required
def api_add_domain():
    domain = normalize_domain(payload().get("domain"))
    if not domain:
        return fail("Enter a valid domain such as example.com.")
    add_blocked_domain(domain, db_path=FIREWALL_DB)
    notify_firewall_reload()
    log_general_history(current_user(), "Block Domain", domain)
    return ok(domain=domain)


@app.delete("/api/domains")
@admin_required
def api_remove_domain():
    domain = normalize_domain(payload().get("domain"))
    if not domain:
        return fail("Invalid domain.")
    remove_blocked_domain(domain, db_path=FIREWALL_DB)
    notify_firewall_reload()
    log_general_history(current_user(), "Unblock Domain", domain)
    return ok(domain=domain)


@app.get("/api/blocked-ips")
@login_required
def api_blocked_ips():
    ensure_blocked_ips_schema(FIREWALL_DB)
    with db(FIREWALL_DB) as conn:
        rows = conn.execute(
            "SELECT ip, domain, expires_at, reason FROM blocked_ips ORDER BY ip"
        ).fetchall()
    return ok(ips=[dict(row) for row in rows])


@app.post("/api/blocked-ips")
@admin_required
def api_add_blocked_ip():
    ip = valid_ip(payload().get("ip"))
    if not ip:
        return fail("Enter a valid IPv4 or IPv6 address.")
    ensure_blocked_ips_schema(FIREWALL_DB)
    with db(FIREWALL_DB) as conn:
        conn.execute(
            """INSERT INTO blocked_ips(ip, domain, expires_at, reason)
               VALUES (?, NULL, NULL, 'manual')
               ON CONFLICT(ip) DO UPDATE SET
                 domain=NULL, expires_at=NULL, reason='manual'""",
            (ip,),
        )
    notify_firewall_reload()
    log_general_history(current_user(), "Block IP", ip)
    return ok(ip=ip)


@app.delete("/api/blocked-ips")
@admin_required
def api_remove_blocked_ip():
    ip = valid_ip(payload().get("ip"))
    if not ip:
        return fail("Invalid IP address.")
    with db(FIREWALL_DB) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    notify_firewall_reload()
    log_general_history(current_user(), "Unblock IP", ip)
    return ok(ip=ip)


@app.get("/api/signatures")
@login_required
def api_signatures():
    rows = get_all_signatures(FIREWALL_DB)
    signatures = [
        {
            "id": row[0],
            "app_name": row[1],
            "pattern": row[2],
            "ip_range": row[3],
            "protocol": row[4],
            "domain_pattern": row[5],
        }
        for row in rows
    ]
    return ok(signatures=signatures)


@app.post("/api/signatures")
@admin_required
def api_add_signature():
    data = payload()
    app_name = str(data.get("app_name") or "").strip()
    pattern = str(data.get("pattern") or "").strip() or None
    domain_pattern = str(data.get("domain_pattern") or "").strip() or None
    ip_range = str(data.get("ip_range") or "").strip() or None
    protocol = str(data.get("protocol") or "ANY").strip().upper()
    if not app_name:
        return fail("Application/service name is required.")
    if not any((pattern, domain_pattern, ip_range)):
        return fail("Provide a host pattern, domain pattern, or IP range.")
    if protocol not in {"ANY", "TCP", "UDP", "ICMP"}:
        return fail("Unsupported protocol.")
    add_signature(app_name, pattern, ip_range, protocol, domain_pattern, FIREWALL_DB)
    notify_firewall_reload()
    log_general_history(current_user(), "Add App Signature", app_name)
    return ok()


@app.delete("/api/signatures/<int:signature_id>")
@admin_required
def api_remove_signature(signature_id):
    remove_signature(signature_id=signature_id, db_path=FIREWALL_DB)
    notify_firewall_reload()
    log_general_history(current_user(), "Remove App Signature", str(signature_id))
    return ok()


@app.get("/api/devices")
@login_required
def api_devices():
    detected = detect_devices()
    blocked = {ip: mac for ip, mac in get_blocked_devices()}
    devices = []
    seen = set()
    for ip, mac in detected:
        seen.add(ip)
        devices.append({"ip": ip, "mac": mac, "blocked": ip in blocked})
    for ip, mac in blocked.items():
        if ip not in seen:
            devices.append({"ip": ip, "mac": mac, "blocked": True})
    return ok(devices=devices)


@app.post("/api/devices/block")
@admin_required
def api_block_device():
    ip = valid_ip(payload().get("ip"))
    if not ip:
        return fail("Invalid device IP.")
    add_blocked_device(ip)
    blocked = {row[0] for row in get_blocked_devices()}
    if ip not in blocked:
        return fail("Could not block the device. Ensure it is visible in the ARP table.", 409)
    log_general_history(current_user(), "Block Device", ip)
    return ok(ip=ip)


@app.post("/api/devices/unblock")
@admin_required
def api_unblock_device():
    ip = valid_ip(payload().get("ip"))
    if not ip:
        return fail("Invalid device IP.")
    remove_blocked_device(ip)
    log_general_history(current_user(), "Unblock Device", ip)
    return ok(ip=ip)


@app.get("/api/rules")
@login_required
def api_rules():
    with db(FIREWALL_DB) as conn:
        rows = conn.execute(
            "SELECT id, username, ip, port, protocol, action FROM firewall_rules ORDER BY id DESC"
        ).fetchall()
    return ok(rules=[dict(row) for row in rows])


@app.post("/api/rules")
@admin_required
def api_add_rule():
    data = payload()
    ip = valid_ip(data.get("ip"))
    port = str(data.get("port") or "ANY").strip().upper()
    protocol = str(data.get("protocol") or "ANY").strip().upper()
    action = str(data.get("action") or "BLOCK").strip().upper()

    if not ip:
        return fail("Enter a valid target IP address.")
    if port != "ANY":
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            return fail("Port must be ANY or a number from 1 to 65535.")
    if protocol not in {"TCP", "UDP", "ICMP", "ANY"}:
        return fail("Unsupported protocol.")
    if action not in {"BLOCK", "ALLOW"}:
        return fail("Unsupported action.")
    if protocol in {"ICMP", "ANY"} and port != "ANY":
        return fail("Port must be ANY for ICMP or ANY protocol.")

    with db(FIREWALL_DB) as conn:
        duplicate = conn.execute(
            """SELECT id FROM firewall_rules
               WHERE ip=? AND port=? AND protocol=? AND action=?""",
            (ip, port, protocol, action),
        ).fetchone()
        if duplicate:
            return fail("This firewall rule already exists.", 409)
        cur = conn.execute(
            """INSERT INTO firewall_rules(username, ip, port, protocol, action)
               VALUES (?, ?, ?, ?, ?)""",
            (current_user(), ip, port, protocol, action),
        )
        rule_id = cur.lastrowid

    applied, message = apply_netsh_rule(rule_id, ip, port, protocol, action)
    log_general_history(
        current_user(),
        "Add Rule",
        f"{action} {protocol} {ip}:{port}; enforcement={applied}",
    )
    return ok(rule_id=rule_id, applied=applied, message=message)


@app.delete("/api/rules/<int:rule_id>")
@admin_required
def api_remove_rule(rule_id):
    with db(FIREWALL_DB) as conn:
        row = conn.execute(
            "SELECT ip, port, protocol, action FROM firewall_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            return fail("Rule not found.", 404)
        conn.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
    delete_netsh_rule(rule_id)
    log_general_history(current_user(), "Remove Rule", f"Rule #{rule_id}")
    return ok()


@app.get("/api/threats")
@login_required
def api_threats():
    with db(THREATS_DB) as conn:
        rows = conn.execute(
            """SELECT id, timestamp, src_ip, dst_ip, protocol, severity, description
               FROM threats ORDER BY id DESC LIMIT 300"""
        ).fetchall()
    return ok(threats=[dict(row) for row in rows])


@app.delete("/api/threats")
@admin_required
def api_clear_threats():
    with db(THREATS_DB) as conn:
        conn.execute("DELETE FROM threats")
    log_general_history(current_user(), "Clear Threats", "Cleared threat monitor")
    return ok()


@app.get("/api/history")
@login_required
def api_history():
    search = request.args.get("search", "").strip()
    try:
        limit = min(500, max(1, int(request.args.get("limit", "200"))))
    except ValueError:
        limit = 200

    query = "SELECT id, username, action, description, timestamp FROM history"
    params = []
    if search:
        like = f"%{search}%"
        query += " WHERE username LIKE ? OR action LIKE ? OR description LIKE ? OR timestamp LIKE ?"
        params.extend([like, like, like, like])
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with db(GENERAL_HISTORY_DB) as conn:
        rows = conn.execute(query, params).fetchall()
    return ok(history=[dict(row) for row in rows])


@app.get("/api/settings")
@login_required
def api_settings_get():
    return ok(settings=load_settings())


@app.put("/api/settings")
@admin_required
def api_settings_put():
    incoming = payload()
    settings = load_settings()
    for key in DEFAULT_SETTINGS:
        if key in incoming:
            settings[key] = bool(incoming[key])
    save_settings_file(settings)
    apply_runtime_settings(settings)
    auto_ok, auto_message = set_autostart(settings.get("auto_start", False))
    notify_firewall_reload()
    log_general_history(current_user(), "Update Settings", json.dumps(settings, sort_keys=True))
    return ok(settings=settings, autostart={"ok": auto_ok, "message": auto_message})


@app.post("/api/backup")
@admin_required
def api_backup():
    target = BACKUP_DIR / datetime.now().strftime("%Y%m%d_%H%M%S")
    target.mkdir(parents=True, exist_ok=True)
    copied = []
    for path in (FIREWALL_DB, USERS_DB, GENERAL_HISTORY_DB, FIREWALL_LOGS_DB, THREATS_DB):
        source = Path(path)
        if source.exists():
            shutil.copy2(source, target / source.name)
            copied.append(source.name)
    log_general_history(current_user(), "Backup Databases", str(target))
    return ok(folder=str(target), copied=copied)


@app.get("/api/users")
@admin_required
def api_users():
    with db(USERS_DB) as conn:
        rows = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    return ok(users=[dict(row) for row in rows])


@app.post("/api/users")
@admin_required
def api_add_user():
    data = payload()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    role = str(data.get("role") or "user").lower()
    if len(username) < 3:
        return fail("Username must be at least 3 characters.")
    if len(password) < 8:
        return fail("Password must be at least 8 characters.")
    if role not in {"user", "admin"}:
        return fail("Role must be user or admin.")
    if not create_user(username, password, role, db_path=USERS_DB):
        return fail("User already exists.", 409)
    log_general_history(current_user(), "Add User", f"{username} ({role})")
    return ok()


@app.put("/api/users/<username>")
@admin_required
def api_update_user(username):
    data = payload()
    password = str(data.get("password") or "")
    role = str(data.get("role") or "").lower().strip()
    changed = False

    if password:
        if len(password) < 8:
            return fail("Password must be at least 8 characters.")
        if not set_password(username, password, db_path=USERS_DB):
            return fail("User not found.", 404)
        changed = True

    if role:
        if role not in {"user", "admin"}:
            return fail("Role must be user or admin.")
        if username == current_user() and role != "admin":
            return fail("You cannot remove your own admin role while signed in.", 409)
        with db(USERS_DB) as conn:
            cur = conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            if cur.rowcount == 0:
                return fail("User not found.", 404)
        changed = True

    if not changed:
        return fail("No changes supplied.")

    log_general_history(current_user(), "Update User", username)
    return ok()


@app.delete("/api/users/<username>")
@admin_required
def api_delete_user(username):
    if username == current_user():
        return fail("You cannot delete the account currently signed in.", 409)
    with db(USERS_DB) as conn:
        cur = conn.execute("DELETE FROM users WHERE username=?", (username,))
        if cur.rowcount == 0:
            return fail("User not found.", 404)
    log_general_history(current_user(), "Remove User", username)
    return ok()


def parse_args():
    parser = argparse.ArgumentParser(description="PyreWall browser-based firewall console")
    parser.add_argument(
        "--host",
        default=os.environ.get("PYREWALL_WEB_HOST", "127.0.0.1"),
        help="Bind address. Use 0.0.0.0 only for a trusted LAN.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PYREWALL_WEB_PORT", "8765")),
    )
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main():
    init_web_schema()
    settings = load_settings()
    apply_runtime_settings(settings)
    args = parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "[Pyrewall] WARNING: web console is reachable beyond localhost. "
            "Use only on a trusted LAN and protect the host firewall."
        )

    print(f"[Pyrewall] Web console: http://{args.host}:{args.port}")
    print("[Pyrewall] Run this process as Administrator for firewall enforcement.")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
