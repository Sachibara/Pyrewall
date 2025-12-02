import os
import sqlite3
import json
from pyrewall.db.paths import BASE_DIR  # ensure this is imported along with other pyrewall imports
MARKER_FILE = os.path.join(BASE_DIR, "first_run.json")
from PyQt6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QHBoxLayout, QCheckBox)
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtGui import QPixmap
from pyrewall.core.security import validate_user, is_admin
from pyrewall.db.storage import log_general_history



# Lazy import to avoid circular dependency later
def import_homepage():
    from pyrewall.ui.dashboard import HomePage
    return HomePage


class LoginPage(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Admin Login Page')
        self.setFixedSize(600, 400)

        main_layout = QHBoxLayout()

        # Left panel with logo
        left_layout = QVBoxLayout()
        left_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label = QLabel()
        logo_path = os.path.join(os.path.dirname(__file__), "FFLogo.png")
        logo_pixmap = QPixmap(logo_path)
        if logo_pixmap.isNull():
            print("[Pyrewall] ⚠️ Logo not found:", logo_path)
        logo_label.setPixmap(
            logo_pixmap.scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        )
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(logo_label)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)
        left_widget.setStyleSheet("background-color: #F6F6F6;")

        # Right panel (login form)
        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.setSpacing(20)

        # --- One-time first-run credentials banner (if marker exists) ---
        self.first_run_banner = None
        try:
            if os.path.exists(MARKER_FILE):
                try:
                    with open(MARKER_FILE, "r", encoding="utf-8") as mf:
                        m = json.load(mf)
                    creds = m.get("credentials", {})
                    uname = creds.get("username", "admin")
                    pwd = creds.get("password", "password")
                    banner_text = (f"First-time default admin credentials created:\n\n"
                                   f"username: {uname}\npassword: {pwd}\n\n"
                                   "Please log in and change the password in Settings.")
                    self.first_run_banner = QLabel(banner_text)
                    self.first_run_banner.setWordWrap(True)
                    self.first_run_banner.setStyleSheet("background-color: #FFF9C4; padding:8px; border-radius:6px;")
                    right_layout.addWidget(self.first_run_banner)
                except Exception:
                    # ignore marker read errors
                    pass
        except Exception:
            pass


        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Username')
        self.username_input.setFixedHeight(40)
        self.username_input.setFixedWidth(250)
        self.username_input.setStyleSheet("background-color: white; border: 1px solid #ccc; border-radius: 5px;")
        right_layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setFixedHeight(40)
        self.password_input.setFixedWidth(250)
        self.password_input.setStyleSheet("background-color: white; border: 1px solid #ccc; border-radius: 5px;")
        right_layout.addWidget(self.password_input)

        self.remember_me_checkbox = QCheckBox('Remember me')
        self.remember_me_checkbox.setStyleSheet("color: white;")
        right_layout.addWidget(self.remember_me_checkbox)

        forgot_details = QLabel('<a href="#">forgot details?</a>')
        forgot_details.setOpenExternalLinks(True)
        forgot_details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        forgot_details.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 12px;
            }
            QLabel:hover {
                color: #00BFFF;  /* optional: light blue on hover */
            }
        """)

        self.sign_in_button = QPushButton('Sign in')
        self.sign_in_button.setFixedHeight(40)
        self.sign_in_button.setStyleSheet("background-color: #007BFF; color: white; border-radius: 5px;")
        self.sign_in_button.clicked.connect(self.sign_in)
        right_layout.addWidget(self.sign_in_button)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        right_widget.setStyleSheet("background-color: #1E60B0;")

        main_layout.addWidget(left_widget, 1)
        main_layout.addWidget(right_widget, 2)

        self.setLayout(main_layout)

        # Support pressing Enter to login
        self.username_input.installEventFilter(self)
        self.password_input.installEventFilter(self)

    def eventFilter(self, source, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Return:
            self.sign_in()
            return True
        return super().eventFilter(source, event)

    def sign_in(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please enter both username and password.")
            return

        try:
            # validate against hashed password stored in canonical DB
            if validate_user(username, password):
                role = "admin" if is_admin(username) else "user"
                log_general_history(username, "Login Success", f"User login ({role})")

                # If first-run marker exists, remove it now that the user logged in (so banner disappears next time).
                try:
                    if os.path.exists(MARKER_FILE):
                        os.remove(MARKER_FILE)
                except Exception:
                    pass

                self.open_home_page(username, role)

            else:
                QMessageBox.critical(self, "Error", "Invalid username or password.")
                log_general_history(username, "Login Failed", "User login attempt failed.")
        except Exception as e:
            # Print full traceback to console for debugging (will show file and line)
            import traceback
            tb = traceback.format_exc()
            print("=== LOGIN EXCEPTION TRACEBACK ===")
            print(tb)
            print("=== END TRACEBACK ===")
            # show simplified message in UI but keep full trace in console
            QMessageBox.critical(self, "Database Error", f"Login failed: {str(e)} (see console for traceback)")

    def open_home_page(self, username, role):
        """Open dashboard with role-based tabs."""
        from pyrewall.ui.dashboard import HomePage
        self.home_page = HomePage(username, role)
        self.home_page.show()
        self.close()

