# Pyrewall — Next Generation Firewall

Pyrewall is a Windows-focused firewall and network monitoring desktop application built with Python and PyQt6. It combines network visibility, filtering, device control, firewall rules, threat monitoring, history, and administration in a desktop interface.

## Project Links

- **Desktop source:** https://github.com/Sachibara/Pyrewall
- **Public PyreWall Web workspace:** https://portfolio-github-io-five-pi.vercel.app/projects/pyrewall-web/
- **Portfolio:** https://portfolio-github-io-five-pi.vercel.app/

## Overview

Pyrewall was developed as a BSIT Network Technology capstone project. The goal is to provide a practical desktop control layer for monitoring and managing network activity from a Windows host.

The application uses a modular structure that separates firewall logic, network utilities, persistence, and the PyQt6 user interface.

## Core Features

- Start and stop the firewall engine from the desktop dashboard
- Detect connected devices through ARP-based network discovery
- Block and unblock devices using IP/MAC information and Windows Firewall rules
- Manage blocked domains and IP addresses
- DNS-based domain filtering support
- Firewall rule management
- Threat and security-event views
- Activity and history logging
- Role-aware user management
- SQLite-backed local persistence
- Packaging-aware database paths for desktop deployment

## Technology Stack

- **Python**
- **PyQt6**
- **SQLite**
- **pydivert / WinDivert**
- **DNS and socket networking**
- **Windows Firewall / netsh**
- **ARP-based device discovery**
- **Threaded background processing**

## Project Structure

```text
Pyrewall/
├── main.py
├── core/
│   ├── firewall_thread.py
│   ├── devices.py
│   ├── dns_proxy.py
│   └── ...
├── db/
│   ├── paths.py
│   ├── storage.py
│   └── ...
├── ui/
│   ├── dashboard.py
│   ├── login.py
│   └── tabs/
└── assets/
```

## How It Works

The PyQt6 interface communicates with a background firewall controller so network processing does not block the UI thread. Network and firewall state is stored locally in SQLite databases. Device controls use Windows networking utilities and firewall rules, while domain filtering is supported by DNS and IP-based mechanisms.

## Running the Project

Pyrewall is designed primarily for Windows because several features depend on Windows Firewall, ARP tooling, and WinDivert.

A typical development setup requires Python 3, PyQt6, the project's networking dependencies, and administrator privileges for features that modify firewall/network behavior.

```bash
python main.py
```

Some firewall, DNS, and device-control features require running the application with administrator privileges.

## Current Status

This repository contains the active implementation of Pyrewall. The project includes working UI, database, network-control, and firewall-engine modules while continuing to evolve as a capstone and portfolio project.

## Developer

**Jim Rodmark Camus**  
BSIT — Network Technology  
GitHub: [@Sachibara](https://github.com/Sachibara)

## Portfolio

View the developer portfolio source and related projects through the [Sachibara GitHub profile](https://github.com/Sachibara).
