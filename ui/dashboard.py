# pyrewall/ui/dashboard.py
import os
import time
import threading
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTabWidget, QPushButton, QMessageBox, QHBoxLayout
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import QTimer, QMetaObject, Qt, Q_ARG

from pyrewall.db.storage import log_general_history

# Import the controller API (preferred) for starting/stopping the firewall thread
try:
    from pyrewall.core.firewall_thread import (
        start_firewall, stop_firewall, is_firewall_running, is_firewall_ready
    )
except Exception as e:
    start_firewall = stop_firewall = is_firewall_running = is_firewall_ready = None
    print(f"[Pyrewall] ⚠️ Could not import firewall controller API: {e}")


from pyrewall.ui.tabs.websites_tab import WebsitesTab
from pyrewall.ui.tabs.devices_tab import DevicesTab
from pyrewall.ui.tabs.apps_tab import AppsTab
from pyrewall.ui.tabs.rules_tab import RulesTab
from pyrewall.ui.tabs.threats_tab import ThreatsTab
from pyrewall.ui.tabs.history_tab import HistoryTab
from pyrewall.ui.tabs.settings_tab import SettingsTab
from pyrewall.ui.tabs.overview_tab import OverviewTab

# canonical DB path so UI starts firewall with same DB as rest of the app
try:
    from pyrewall.db.paths import FIREWALL_DB as CANONICAL_DB
except Exception:
    CANONICAL_DB = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "db", "firewall.db"))


class HomePage(QWidget):
    """Main Pyrewall Dashboard after login"""

    def __init__(self, username: str, role: str = "user"):
        super().__init__()
        self.username = username
        self.role = role

        # --- Window setup ---
        self.setWindowTitle(f"Pyrewall Dashboard - Logged in as {self.username}")
        self.setGeometry(100, 100, 1100, 650)

        # --- Main layout ---
        main_layout = QVBoxLayout()

        # ========== HEADER ==========
        header_layout = QHBoxLayout()

        logo = QLabel()
        from pyrewall.utils.helpers import resource_path
        pixmap = QPixmap(resource_path("ui", "FFLogo.png"))

        if not pixmap.isNull():
            logo.setPixmap(pixmap.scaled(35, 35, Qt.AspectRatioMode.KeepAspectRatio))
        else:
            logo.setText("🧱")

        title_label = QLabel("Pyrewall NGFW Dashboard")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))

        self.status_label = QLabel("Status: 🔴 Stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")

        # Start / Stop / Logout buttons
        self.start_btn = QPushButton("Start Firewall")
        self.start_btn.setStyleSheet("background-color:#28a745;color:white;border-radius:6px;padding:4px 12px;")
        self.start_btn.clicked.connect(self.start_firewall)

        self.stop_btn = QPushButton("Stop Firewall")
        self.stop_btn.setStyleSheet("background-color:#ffc107;color:black;border-radius:6px;padding:4px 12px;")
        self.stop_btn.clicked.connect(self.stop_firewall)

        logout_btn = QPushButton("Logout")
        logout_btn.setStyleSheet("background-color:#dc3545;color:white;border-radius:6px;padding:4px 12px;")
        logout_btn.clicked.connect(self.logout)

        header_layout.addWidget(logo)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)
        header_layout.addWidget(self.start_btn)
        header_layout.addWidget(self.stop_btn)
        header_layout.addWidget(logout_btn)

        main_layout.addLayout(header_layout)

        # Welcome banner
        welcome_label = QLabel(f"Welcome, {self.username} ({role.capitalize()}) 👋")
        welcome_label.setFont(QFont("Helvetica", 18, QFont.Weight.Bold))
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(welcome_label)

        # ========== MAIN TABS ==========
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 6px;
                margin: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0078D7;
                color: white;
            }
            QTabBar::tab:!selected {
                background-color: #E7E7E7;
                color: black;
            }
        """)

        # Tabs
        self.websites_tab = WebsitesTab(self.username)
        self.devices_tab = DevicesTab(self.username)
        self.apps_tab = AppsTab(self.username)

        self.tabs.addTab(self.websites_tab, "🌐 Website Blocking")
        self.tabs.addTab(self.devices_tab, "📡 Devices")
        self.tabs.addTab(self.apps_tab, "🧩 Applications")
        self.tabs.addTab(OverviewTab(self.username), "📊 Overview")
        self.tabs.addTab(ThreatsTab(self.username), "🚨 Threats")
        self.tabs.addTab(RulesTab(self.username), "🛡️ Firewall Rules")
        self.tabs.addTab(HistoryTab(self.username, self.role), "📜 History")
        self.tabs.addTab(SettingsTab(self.username), "⚙️ Settings")

        # 🧑‍💻 ADMIN-ONLY TAB: User Management
        if role.lower() == "admin":
            try:
                from pyrewall.ui.tabs.user_management_tab import UserManagementTab
                self.tabs.addTab(UserManagementTab(self.username), "👥 User Management")
            except Exception as e:
                print(f"[Pyrewall] ⚠️ Could not load User Management tab: {e}")

        main_layout.addWidget(self.tabs)

        self.setLayout(main_layout)

        # Track runtime state (we no longer create FirewallThread ourselves)
        self._is_running = False

        # Initialize UI status based on controller (if available)
        self._refresh_status_from_controller()

        # Ensure button states reflect initial controller state
        self._apply_button_states()

    # ---------------- FIREWALL ---------------- #

    def _set_buttons_state(self, start_enabled: bool, stop_enabled: bool, start_text: str = None, stop_text: str = None):
        """
        Central helper to set button enabled/disabled and allow temporary text changes.
        start_text/stop_text are optional to show "Starting..." / "Stopping..."
        """
        try:
            if start_text is not None:
                self.start_btn.setText(start_text)
            else:
                # keep default label if not provided
                self.start_btn.setText("Start Firewall")
            if stop_text is not None:
                self.stop_btn.setText(stop_text)
            else:
                self.stop_btn.setText("Stop Firewall")

            self.start_btn.setEnabled(bool(start_enabled))
            self.stop_btn.setEnabled(bool(stop_enabled))
        except Exception as e:
            print(f"[Pyrewall] ⚠️ _set_buttons_state error: {e}")

    def _apply_button_states(self):
        """Set button states according to current self._is_running flag."""
        if self._is_running:
            # running -> Start disabled, Stop enabled
            self._set_buttons_state(start_enabled=False, stop_enabled=True)
        else:
            # stopped -> Start enabled, Stop disabled
            self._set_buttons_state(start_enabled=True, stop_enabled=False)

    def _refresh_status_from_controller(self):
        """Query controller for running state and reflect in UI."""
        try:
            running = False
            ready = False

            if callable(is_firewall_running):
                try:
                    running = is_firewall_running()
                except Exception as e:
                    print(f"[Pyrewall] ⚠️ is_firewall_running() call failed: {e}")
                    running = getattr(self, "_is_running", False)

            # Prefer explicit readiness if controller provides it
            if callable(is_firewall_ready):
                try:
                    ready = is_firewall_ready()
                except Exception as e:
                    print(f"[Pyrewall] ⚠️ is_firewall_ready() call failed: {e}")
                    ready = False

            # Decide UI state:
            # - ready -> Running
            # - running but not ready -> Starting (show disabled Start, disabled Stop until ready)
            # - not running -> Stopped
            if ready:
                self._is_running = True
                self.status_label.setText("Status: 🟢 Running")
                self.status_label.setStyleSheet("color: green; font-weight: bold;")
            elif running and not ready:
                # thread alive but not fully ready yet
                self._is_running = True
                self.status_label.setText("Status: 🟡 Starting…")
                self.status_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self._is_running = False
                self.status_label.setText("Status: 🔴 Stopped")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
        except Exception as e:
            print(f"[Pyrewall] ⚠️ Failed to refresh firewall status: {e}")
        finally:
            # Always ensure buttons reflect the final known state
            self._apply_button_states()

    def start_firewall(self):
        """Start the firewall via controller. Uses canonical DB path.
        Runs controller call in a short worker thread and polls readiness.
        """
        # Guard against double start attempts
        if self._is_running:
            QTimer.singleShot(0, lambda: QMessageBox.information(self, "Firewall", "⚙️ Firewall is already running."))
            return

        # immediate UI feedback: disable both buttons while starting
        self._set_buttons_state(start_enabled=False, stop_enabled=False, start_text="Starting…",
                                stop_text="Stop Firewall")

        def _worker():
            try:
                if not callable(start_firewall):
                    # controller missing
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Firewall",
                                                                     "Start not available (controller missing)."))
                    # ensure UI state is refreshed on main thread
                    QTimer.singleShot(0, self._refresh_status_from_controller)
                    return

                # request start (controller launches worker asynchronously)
                started = start_firewall(db_path=CANONICAL_DB)
                if not started:
                    print("[Pyrewall] start_firewall() returned False immediately.")
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Firewall",
                                                                      "❌ Failed to initiate firewall start (see console)."))
                    QTimer.singleShot(0, self._refresh_status_from_controller)
                    return

                # poll for readiness (prefer is_firewall_ready if available)
                poll_timeout = 8.0
                poll_interval = 0.1
                deadline = time.time() + poll_timeout
                ready = False
                while time.time() < deadline:
                    try:
                        if callable(is_firewall_ready):
                            ready = is_firewall_ready()
                        elif callable(is_firewall_running):
                            ready = is_firewall_running()
                        else:
                            ready = False
                    except Exception as e:
                        print(f"[Pyrewall] start worker poll error: {e}")
                        ready = False

                    if ready:
                        break
                    time.sleep(poll_interval)

                if ready:
                    # update internal flag and post UI updates to main thread
                    self._is_running = True
                    print("[Pyrewall] 🔥 Firewall started and ready.")

                    def _on_started():
                        try:
                            self.status_label.setText("Status: 🟢 Running")
                            self.status_label.setStyleSheet("color: green; font-weight: bold;")
                            log_general_history(self.username, "Firewall", "Started firewall")
                            QMessageBox.information(self, "Firewall", "✅ Firewall started successfully.")
                        except Exception:
                            print("[Pyrewall] Firewall started (could not show QMessageBox on main thread).")

                    QTimer.singleShot(0, _on_started)
                else:
                    print("[Pyrewall] ❌ Firewall start timed out waiting for readiness.")
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Firewall",
                                                                      "❌ Firewall did not become ready (timed out)."))

            except Exception as e:
                print(f"[Pyrewall] ❌ start_firewall worker exception: {e}")
                QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Firewall Error",
                                                                  f"Failed to start firewall:\n{e}"))
            finally:
                # always refresh status & button states on main thread at end
                QTimer.singleShot(0, self._refresh_status_from_controller)

        threading.Thread(target=_worker, daemon=True).start()

    def stop_firewall(self):
        """Stop the firewall via controller. Runs controller call in worker thread and polls until thread exits."""
        # if we think it's not running, warn
        if not self._is_running and callable(is_firewall_running) and not is_firewall_running():
            QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Firewall", "⚠️ Firewall is not currently running."))
            return

        # immediate UI feedback: disable both buttons while stopping
        self._set_buttons_state(start_enabled=False, stop_enabled=False, start_text="Start Firewall",
                                stop_text="Stopping…")

        def _worker():
            try:
                if not callable(stop_firewall):
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Firewall",
                                                                     "Stop not available (controller missing)."))
                    QTimer.singleShot(0, self._refresh_status_from_controller)
                    return

                ok = stop_firewall(wait=True, timeout=8.0)

                if ok:
                    self._is_running = False
                    print("[Pyrewall] 🛑 Firewall stopped via controller.")

                    def _on_stopped():
                        try:
                            self.status_label.setText("Status: 🔴 Stopped")
                            self.status_label.setStyleSheet("color: red; font-weight: bold;")
                            log_general_history(self.username, "Firewall", "Stopped firewall")
                            QMessageBox.information(self, "Firewall", "🛑 Firewall stopped successfully.")
                        except Exception:
                            print("[Pyrewall] Firewall stopped (could not show QMessageBox on main thread).")

                    QTimer.singleShot(0, _on_stopped)
                else:
                    print("[Pyrewall] ❌ stop_firewall controller reported join timeout / still alive.")
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Firewall",
                                                                      "❌ Failed to stop firewall cleanly (still alive)."))

            except Exception as e:
                print(f"[Pyrewall] ❌ stop_firewall worker exception: {e}")
                QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Firewall Error",
                                                                  f"Failed to stop firewall:\n{e}"))
            finally:
                QTimer.singleShot(0, self._refresh_status_from_controller)

        threading.Thread(target=_worker, daemon=True).start()

    # ---------------- LOGOUT ---------------- #

    def logout(self):
        """Return to login"""
        from pyrewall.ui.login import LoginPage
        # ensure firewall is stopped when logging out (best-effort)
        try:
            if callable(stop_firewall):
                stop_firewall(wait=False)
        except Exception:
            pass

        self.close()
        self.login_window = LoginPage()
        self.login_window.show()
