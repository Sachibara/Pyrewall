# pyrewall/ui/dashboard.py
import os
import time
import threading
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTabWidget, QPushButton, QMessageBox, QHBoxLayout
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import QObject, pyqtSignal, QTimer, Qt
from pyrewall.db.storage import log_general_history
# Import the controller API (preferred) for starting/stopping the firewall thread
try:
    from pyrewall.core.firewall_thread import (
        start_firewall, stop_firewall, is_firewall_running, is_firewall_ready
    )
except Exception as e:
    start_firewall = stop_firewall = is_firewall_running = is_firewall_ready = None
    print(f"[Pyrewall] ⚠️ Could not import firewall controller API: {e}")

# new import for centralized button styles (place near other imports)
from pyrewall.ui.button_styles import make_button
from pyrewall.ui.tabs.network_control_tab import NetworkControlTab
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

# a tiny helper object to run callables on the Qt main thread
class _MainInvoker(QObject):
    invoke = pyqtSignal(object)

_main_invoker = _MainInvoker()
# ensure calls emitted from worker threads are queued and executed on the Qt main thread
_main_invoker.invoke.connect(lambda fn: fn(), Qt.ConnectionType.QueuedConnection)

def call_on_main(fn):
    """Schedule callable fn to run on the Qt main thread via queued signal."""
    try:
        _main_invoker.invoke.emit(fn)
    except Exception as e:
        print(f"[Pyrewall] call_on_main failed to emit: {e}")


class HomePage(QWidget):
    """Main Pyrewall Dashboard after login"""

    def __init__(self, username: str, role: str = "user"):
        super().__init__()
        self.username = username
        self.role = role

        # --- Window setup ---
        self.setWindowTitle(f"Pyrewall: Next Generation Firewall - Logged in as {self.username}")
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

        title_label = QLabel("Pyrewall NGFW")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))

        self.status_label = QLabel("Status: 🔴 Stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")

        # Start / Stop / Logout buttons
        self.start_btn = make_button("Start Firewall", variant="success", height=28)
        self.start_btn.clicked.connect(self.start_firewall)

        self.stop_btn = make_button("Stop Firewall", variant="warning", height=28)
        self.stop_btn.clicked.connect(self.stop_firewall)

        logout_btn = make_button("Logout", variant="danger", height=28)
        logout_btn.clicked.connect(self._on_logout_clicked)

        header_layout.addWidget(logo)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)
        header_layout.addWidget(self.start_btn)
        header_layout.addWidget(self.stop_btn)
        header_layout.addWidget(logout_btn)

        main_layout.addLayout(header_layout)

        # Welcome banner
        welcome_label = QLabel(f"Welcome, {self.username} 👋")
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

        # --- create Overview first and keep a reference
        self.overview_tab = OverviewTab(self.username)
        self.overview_tab.home = self
        self.tabs.addTab(self.overview_tab, "📊 Overview")

        # create other tabs after overview (so we know their tab indexes)
        self.network_tab = NetworkControlTab(self.username)
        self.network_tab.home = self
        self.tabs.addTab(self.network_tab, "🔧 Network Control")
        self.tabs.addTab(ThreatsTab(self.username), "🚨 Threats")
        self.tabs.addTab(RulesTab(self.username), "🛡️ Firewall Rules")
        self.tabs.addTab(HistoryTab(self.username, self.role), "📜 History")
        self.tabs.addTab(SettingsTab(self.username), "⚙️ Settings")
        if role.lower() == "admin":
            try:
                from pyrewall.ui.tabs.user_management_tab import UserManagementTab
                self.user_mgmt_tab = UserManagementTab(self.username)
                self.tabs.addTab(self.user_mgmt_tab, "👥 User Management")
            except Exception as e:
                print(f"[Pyrewall] ⚠️ Could not load User Management tab: {e}")


        # connect overview card clicks -> tab switch
        self.overview_tab.card_clicked.connect(self._on_overview_card_clicked)

        main_layout.addWidget(self.tabs)

        # set simple back-reference on known tab attributes so tabs can access home (if present)
        try:
            if hasattr(self, "network_tab"):
                self.network_tab.home = self
            if hasattr(self, "user_mgmt_tab"):
                self.user_mgmt_tab.home = self
            # For other tabs that were added inline without named attributes (e.g. RulesTab, ThreatsTab),
            # iterate through tabs and set `.home` where possible
            for i in range(self.tabs.count()):
                w = self.tabs.widget(i)
                try:
                    # do not overwrite if already set
                    if not hasattr(w, "home"):
                        setattr(w, "home", self)
                except Exception:
                    pass
        except Exception:
            pass
        # ----------- end notifier & back-references -----------

        self.setLayout(main_layout)

        # Track runtime state (we no longer create FirewallThread ourselves)
        self._is_running = False

        # Initialize UI status based on controller (if available)
        self._refresh_status_from_controller()

        # Ensure button states reflect initial controller state
        self._apply_button_states()

    def notify_overview_update(self):
        """
        Public method child tabs can call to request OverviewTab refresh.
        This is a bound instance method (so QTimer.singleShot(0, self.notify_overview_update)
        will work without 'missing self' errors).
        """
        try:
            if hasattr(self, "overview_tab") and callable(getattr(self.overview_tab, "refresh_summary", None)):
                # schedule refresh on Qt main thread via _MainInvoker
                try:
                    _main_invoker.invoke.emit(self.overview_tab.refresh_summary)
                except Exception as e:
                    # do not call QTimer.singleShot from a worker thread — log and ignore
                    print(f"[Pyrewall] notify_overview_update: failed to invoke on main thread: {e}")
        except Exception as e:
            print(f"[Pyrewall] notify_overview_update error: {e}")

    def _on_overview_card_clicked(self, key):
        """
        Map overview card keys to tab indexes. Adjust indexes if you change tab order.
        """
        # create a map from keys to tab index (use the exact order you added them)
        mapping = {
            "sites": self.tabs.indexOf(self.network_tab),  # blocked websites live in NetworkControlTab
            "rules": self.tabs.indexOf(self.find_tab("🛡️ Firewall Rules") or self.tabs.widget(0)),
            "devices": self.tabs.indexOf(self.network_tab),
            "users": self.tabs.indexOf(getattr(self, "user_mgmt_tab", None)) if hasattr(self, "user_mgmt_tab") else -1,
            "signatures": self.tabs.indexOf(self.network_tab),
            "threats": self.tabs.indexOf(self.find_tab("🚨 Threats")),
        }

        idx = mapping.get(key, -1)
        if idx is None or idx < 0:
            # fallback: open first tab
            return
        self.tabs.setCurrentIndex(idx)

    # small helper to find tab by title text (optional convenience)
    def find_tab(self, title_text):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == title_text:
                return self.tabs.widget(i)
        return None

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
                    # controller missing — show warning on main thread
                    try:
                        call_on_main(lambda: QMessageBox.warning(self, "Firewall", "Start not available (controller missing)."))
                    except Exception as e:
                        print(f"[Pyrewall] start_firewall: failed to schedule missing-controller warning: {e}")

                    # ensure UI state is refreshed on main thread
                    try:
                        call_on_main(self._refresh_status_from_controller)
                    except Exception as e:
                        print(f"[Pyrewall] start_firewall: failed to schedule _refresh_status_from_controller: {e}")
                    return

                # request start (controller launches worker asynchronously)
                started = start_firewall(db_path=CANONICAL_DB)
                if not started:
                    print("[Pyrewall] start_firewall() returned False immediately.")

                    try:
                        call_on_main(lambda: QMessageBox.critical(self, "Firewall", "❌ Failed to initiate firewall start (see console)."))
                    except Exception as e:
                        print(f"[Pyrewall] start_firewall: failed to schedule critical message: {e}")

                    try:
                        _main_invoker.invoke.emit(self._refresh_status_from_controller)
                    except Exception:
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

                    try:
                        call_on_main(_on_started)
                    except Exception as e:
                        print(f"[Pyrewall] start_firewall: failed to schedule _on_started: {e}")

                else:
                    print("[Pyrewall] ❌ Firewall start timed out waiting for readiness.")

                    try:
                        call_on_main(lambda: QMessageBox.critical(self, "Firewall", "❌ Firewall did not become ready (timed out)."))
                    except Exception as e:
                        print(f"[Pyrewall] start_firewall: failed to schedule timeout critical message: {e}")


            except Exception as e:
                print(f"[Pyrewall] ❌ start_firewall worker exception: {e}")
                try:
                    call_on_main(lambda: QMessageBox.critical(self, "Firewall Error", f"Failed to start firewall:\n{e}"))
                except Exception as ex2:
                    print(f"[Pyrewall] start_firewall: failed to schedule error message: {ex2}")

            finally:
                # always refresh status & button states on main thread at end
                try:
                    call_on_main(self._refresh_status_from_controller)
                except Exception as e:
                    print(f"[Pyrewall] start_firewall: failed to schedule final status refresh: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def stop_firewall(self):
        """Stop the firewall via controller. Ask for confirmation first.
        Runs controller call in worker thread and polls until thread exits."""
        # if we think it's not running, warn
        if not self._is_running and callable(is_firewall_running) and not is_firewall_running():
            QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Firewall", "⚠️ Firewall is not currently running."))
            return

        # Ask user for confirmation on main thread
        resp = QMessageBox.question(
            self,
            "Confirm Stop Firewall",
            "Are you sure you want to stop the firewall? Stopping it will disable active protections.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if resp != QMessageBox.StandardButton.Yes:
            # user cancelled — ensure UI returns to correct state
            try:
                call_on_main(self._refresh_status_from_controller)
            except Exception as e:
                print(f"[Pyrewall] _on_logout_clicked: failed to schedule status refresh: {e}")
            return

        # immediate UI feedback: disable both buttons while stopping
        self._set_buttons_state(start_enabled=False, stop_enabled=False, start_text="Start Firewall",
                                stop_text="Stopping…")

        def _worker():
            try:
                if not callable(stop_firewall):
                    try:
                        call_on_main(lambda: QMessageBox.warning(self, "Firewall", "Stop not available (controller missing)."))
                    except Exception as e:
                        print(f"[Pyrewall] stop_firewall: failed to schedule missing-controller warning: {e}")

                    try:
                        call_on_main(self._refresh_status_from_controller)
                    except Exception as e:
                        print(f"[Pyrewall] stop_firewall: failed to schedule _refresh_status_from_controller: {e}")
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

                    try:
                        call_on_main(_on_stopped)
                    except Exception as e:
                        print(f"[Pyrewall] stop_firewall: failed to schedule _on_stopped: {e}")

                else:
                    print("[Pyrewall] ❌ stop_firewall controller reported join timeout / still alive.")

                    try:
                        call_on_main(lambda: QMessageBox.critical(self, "Firewall", "❌ Failed to stop firewall cleanly (still alive)."))
                    except Exception as e:
                        print(f"[Pyrewall] stop_firewall: failed to schedule failed-stop critical message: {e}")


            except Exception as e:
                print(f"[Pyrewall] ❌ stop_firewall worker exception: {e}")

                try:
                    call_on_main(lambda: QMessageBox.critical(self, "Firewall Error", f"Failed to stop firewall:\n{e}"))
                except Exception as ex2:
                    print(f"[Pyrewall] stop_firewall: failed to schedule error message: {ex2}")

            finally:
                try:
                    call_on_main(self._refresh_status_from_controller)
                except Exception as e:
                    print(f"[Pyrewall] stop_firewall: failed to schedule final status refresh: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    # ---------------- LOGOUT ---------------- #

    def _on_logout_clicked(self):
        """Handler wired to the logout button only — asks confirmation then calls logout()."""
        resp = QMessageBox.question(
            self,
            "Confirm Logout",
            "Are you sure you want to logout? Unsaved changes may be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if resp != QMessageBox.StandardButton.Yes:
            # user cancelled — refresh UI state and return
            try:
                call_on_main(self._refresh_status_from_controller)
            except Exception as e:
                print(f"[Pyrewall] _on_logout_clicked: failed to schedule status refresh: {e}")
            return

        # user confirmed -> perform actual logout (non-confirming method)
        try:
            self.logout()
        except Exception as e:
            print(f"[Pyrewall] ⚠️ _on_logout_clicked error calling logout(): {e}")

    def logout(self):
        """Return to login without stopping the firewall (non-confirming)."""
        from pyrewall.ui.login import LoginPage

        # Log to history (optional; keep if you want a record)
        try:
            log_general_history(self.username, "User", "Logged out")
        except Exception:
            pass

        # close this window and show login page
        try:
            self.close()
            self.login_window = LoginPage()
            self.login_window.show()
        except Exception as e:
            print(f"[Pyrewall] ⚠️ logout error: {e}")
