"""
Pyrewall Package Initialization

This file marks Pyrewall as a Python package and ensures essential paths and
environment variables are ready before importing any core or UI modules.
"""

import os
import sys

# Ensure DLL directory is on PATH
dll_dir = os.path.join(os.path.dirname(__file__), "assets", "dll")
if os.path.exists(dll_dir) and dll_dir not in os.environ.get("PATH", ""):
    os.environ["PATH"] += os.pathsep + dll_dir