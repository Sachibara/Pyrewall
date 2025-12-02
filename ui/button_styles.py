# pyrewall/ui/button_styles.py
from PyQt6.QtWidgets import QPushButton
from PyQt6.QtCore import QSize

# Centralized button style helper.
# Usage:
#   from pyrewall.ui.button_styles import make_button
#   btn = make_button("Label", variant="primary", height=28, width=120)
#
# Variants: 'primary' (blue), 'success' (green), 'warning' (amber), 'danger' (red), 'ghost' (transparent)
# This keeps visual identity consistent across the app.

_VARIANT_COLORS = {
    "primary": {"bg": "#0078D7", "fg": "white"},
    "success": {"bg": "#28a745", "fg": "white"},
    "warning": {"bg": "#ffc107", "fg": "black"},
    "danger": {"bg": "#dc3545", "fg": "white"},
    "ghost": {"bg": "transparent", "fg": "#101317"},
}

_BASE_STYLE = "border-radius:6px;padding:4px 12px;font-weight:bold;"

def _variant_style(variant: str) -> str:
    v = _VARIANT_COLORS.get(variant, _VARIANT_COLORS["primary"])
    bg = v["bg"]
    fg = v["fg"]
    # subtle hover darken using rgba overlay will not be precise cross-platform; keep simple
    return f"background-color:{bg};color:{fg};{_BASE_STYLE}"

def make_button(text: str, variant: str = "primary", height: int | None = None, width: int | None = None, object_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if object_name:
        btn.setObjectName(object_name)
    # apply stylesheet
    btn.setStyleSheet(_variant_style(variant))
    # set sizes if provided
    if height is not None:
        try:
            btn.setFixedHeight(int(height))
        except Exception:
            pass
    if width is not None:
        try:
            btn.setFixedWidth(int(width))
        except Exception:
            pass
    return btn
