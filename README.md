# PyreWall — Web-Based Next Generation Firewall

PyreWall is now available as a **browser-managed Windows firewall and network control system**. The browser is the administration interface; the actual firewall engine still runs locally on the Windows host so it can use WinDivert, Windows Firewall, ARP, DNS filtering, SQLite, and the existing PyreWall packet-processing code.

This keeps the original capstone requirements while replacing the PyQt6 control surface with a responsive web console.

## Web Firewall Features

### Firewall Engine
- Start and stop the existing WinDivert firewall worker from the browser
- Live engine state: stopped, starting, or WinDivert-ready
- Administrator privilege detection
- Local Windows-host control plane
- Existing HTTP Host, TLS SNI, IP, DNS, and application-signature filtering

### Network Control
- Add and remove blocked websites/domains
- Resolve blocked domains to IP addresses
- Manual blocked IP management
- Manual IP blocks are preserved when domain-derived IPs are refreshed
- Connected-device discovery from the ARP table
- Device block/unblock using ARP and Windows Firewall rules
- Admin-defined application/service signatures
- No hardcoded application/service list

### Firewall Rules
- Custom target IP
- Port or ANY
- TCP / UDP / ICMP / ANY
- BLOCK / ALLOW
- Rules stored in SQLite
- On Windows, new web-created rules are also applied to Windows Firewall through `netsh`

### Monitoring
- Live upload/download throughput graph
- Blocked-domain/IP/device counts
- Firewall-rule and signature counts
- Threat/IDS event viewer
- Activity/history search

### Administration
- Existing PBKDF2-hashed PyreWall accounts
- Admin/user roles
- Add users
- Change passwords
- Change roles
- Remove users
- CSRF protection for state-changing web actions
- Secure session cookies
- Localhost binding by default

### Settings and Maintenance
- Auto-start the web console on Windows login
- Detailed logging preference
- Dark/light browser interface
- DNS proxy preference
- Windows Firewall/netsh preference
- SQLite database backup

## Architecture

```text
Browser
   │
   │ HTTP on localhost / trusted LAN
   ▼
Flask Web Console (web_app.py)
   │
   ├── Existing PyreWall authentication / SQLite
   ├── Existing firewall_thread controller
   ├── Existing domain + IP filtering
   ├── Existing app-signature storage
   ├── Existing device block/unblock logic
   └── Windows Firewall / WinDivert / DNS / ARP
```

The web interface does **not** replace the Windows firewall engine with browser code. Browsers cannot capture or drop arbitrary operating-system packets. Instead, the web application controls the same privileged local Python engine that the desktop UI used.

## Project Structure

```text
Pyrewall/
├── web_app.py                  # Flask web firewall backend
├── run_web_admin.bat           # Windows elevated launcher
├── requirements-web.txt        # Web/runtime dependencies
├── web/
│   ├── templates/
│   │   ├── login.html
│   │   └── dashboard.html
│   └── static/
│       ├── styles.css
│       └── app.js
├── core/                       # Firewall engine and network controls
├── db/                         # SQLite databases and persistence
├── assets/dll/                 # WinDivert runtime
├── ui/                         # Original PyQt6 desktop UI (retained)
└── main.py                     # Original desktop entry point
```

## Windows Setup

PyreWall requires Windows for full enforcement because WinDivert, `netsh advfirewall`, and ARP device controls are Windows-specific.

From the repository directory:

```powershell
python -m pip install -r requirements-web.txt
```

Then either right-click **`run_web_admin.bat` → Run as administrator**, or launch manually from an elevated terminal:

```powershell
python web_app.py
```

Open:

```text
http://127.0.0.1:8765
```

The server binds to localhost by default so the firewall administration console is not exposed to other devices.

## Trusted-LAN Administration

If the Windows machine is acting as your gateway/hotspot and you intentionally want to administer PyreWall from another device on the same trusted LAN:

```powershell
python web_app.py --host 0.0.0.0 --port 8765
```

Then browse to the Windows host's LAN IP and port 8765.

Only use this mode on a trusted network. Do not expose the PyreWall web console directly to the public internet.

## Accounts

The web version uses the existing `users.db` and `core/security.py` password hashing/role system.

If a database has no administrator account, the existing security module creates a fallback admin account. Change the password immediately from **User Management** after first login.

## Web API Security

- Authenticated Flask sessions
- Admin authorization on firewall-changing endpoints
- CSRF token validation for POST/PUT/PATCH/DELETE requests
- `HttpOnly` and `SameSite=Strict` session cookies
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- restrictive Content Security Policy
- localhost-only default binding

## Important Deployment Note

A real PyreWall firewall **cannot be hosted on Vercel or another normal serverless web host** and still control your Windows computer's packets. WinDivert and Windows Firewall must run on the Windows machine being protected or acting as the network gateway.

The web version is therefore a local/self-hosted browser application. You may place a reverse proxy or private VPN in front of it for remote administration, but the Python firewall backend must remain on the Windows host.

## Original Desktop Version

The PyQt6 desktop interface remains in the repository and can still be launched with:

```powershell
python main.py
```

The desktop and web interfaces share the same core firewall modules and SQLite data model.

## Technology Stack

- Python
- Flask
- Vanilla HTML/CSS/JavaScript
- SQLite
- pydivert / WinDivert
- dnslib
- psutil
- Windows Firewall / netsh
- ARP-based device discovery
- PBKDF2-HMAC-SHA256 password hashing

## Developer

**Jim Rodmark Camus**  
BSIT — Network Technology  
GitHub: [@Sachibara](https://github.com/Sachibara)
