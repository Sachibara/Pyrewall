import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QHBoxLayout, QMessageBox, QComboBox
)
from PyQt6.QtGui import QFont
from pyrewall.ui.button_styles import make_button
from pyrewall.db.storage import log_general_history
from pyrewall.core.security import create_user, set_password



DB_PATH = "pyrewall/db/users.db"


class UserManagementTab(QWidget):
    """Admin-only User Management Interface"""
    def __init__(self, username):
        super().__init__()
        self.username = username

        layout = QVBoxLayout()
        title = QLabel("👤 User Management (Admin Only)")
        title.setFont(QFont("Helvetica", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # --- Input fields ---
        input_layout = QHBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        input_layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        input_layout.addWidget(self.password_input)

        self.role_input = QComboBox()
        self.role_input.addItems(["user", "admin"])
        input_layout.addWidget(self.role_input)

        add_btn = make_button("Add User", variant="primary", height=28)
        update_btn = make_button("Update Password", variant="primary", height=28)
        remove_btn = make_button("Remove User", variant="danger", height=28)
        refresh_btn = make_button("Refresh", variant="primary", height=28)
        input_layout.addWidget(add_btn)
        input_layout.addWidget(update_btn)
        input_layout.addWidget(remove_btn)
        input_layout.addWidget(refresh_btn)

        layout.addLayout(input_layout)

        # --- User list ---
        self.user_list = QListWidget()
        layout.addWidget(self.user_list)
        self.setLayout(layout)

        # --- Connect buttons ---
        add_btn.clicked.connect(self.add_user)
        update_btn.clicked.connect(self.update_password)
        remove_btn.clicked.connect(self.remove_user)
        refresh_btn.clicked.connect(self.load_users)

        # --- Initialize users table ---
        self._init_user_table()
        self.load_users()

    # ====================================================
    # 🧱 DATABASE HANDLING
    # ====================================================

    def _init_user_table(self):
        """Ensure 'users' table exists."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'user'
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Pyrewall] users.db init error: {e}")

    def load_users(self):
        """Load all users into list."""
        self.user_list.clear()
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT username, role FROM users")
            users = cur.fetchall()
            conn.close()

            if not users:
                self.user_list.addItem("(No users found)")
                return

            for u, r in users:
                tag = "⭐" if r == "admin" else "👤"
                self.user_list.addItem(f"{tag} {u} ({r})")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load users:\n{e}")

    # ====================================================
    # ➕ ADD USER
    # ====================================================

    def add_user(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        role = self.role_input.currentText()

        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please fill out username and password.")
            return

        try:
            from pyrewall.core.security import create_user
            created = create_user(username, password, role, db_path=DB_PATH)
            if not created:
                QMessageBox.warning(self, "Warning", "User already exists.")
                return
            self.load_users()
            log_general_history(self.username, "Add User", f"Added new user: {username} ({role})")
            QMessageBox.information(self, "Success", f"✅ User '{username}' added successfully.")
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add user:\n{e}")

    # ====================================================
    # 🔑 UPDATE PASSWORD
    # ====================================================

    def update_password(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please provide username and new password.")
            return

        try:
            from pyrewall.core.security import set_password
            ok = set_password(username, password, db_path=DB_PATH)
            if not ok:
                QMessageBox.warning(self, "Warning", "User not found.")
                return
            self.load_users()
            log_general_history(self.username, "Update User", f"Updated password for user: {username}")
            QMessageBox.information(self, "Updated", f"🔑 Password for '{username}' updated.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update password:\n{e}")

    # ====================================================
    # ❌ REMOVE USER
    # ====================================================

    def remove_user(self):
        selected_item = self.user_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Warning", "Please select a user to remove.")
            return

        text = selected_item.text()
        username = text.split()[1] if len(text.split()) > 1 else None

        if not username or username == self.username:
            QMessageBox.warning(self, "Warning", "You cannot delete the currently logged-in admin.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            self.load_users()
            log_general_history(self.username, "Remove User", f"Removed user: {username}")
            QMessageBox.information(self, "Removed", f"❎ User '{username}' has been removed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove user:\n{e}")
