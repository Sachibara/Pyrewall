import os

def check_dependencies():
    dlls = ["WinDivert.dll", "WinDivert64.sys"]
    missing = []
    dll_path = os.path.join(os.path.dirname(__file__), "..", "assets", "dll")
    for dll in dlls:
        if not os.path.exists(os.path.join(dll_path, dll)):
            missing.append(dll)
    return missing
