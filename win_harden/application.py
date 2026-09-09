"""Application object: palette, stylesheet, and the main window.

The Fedora app loaded a CSS file at APPLICATION priority so it could override
Adwaita while still losing to a user's own gtk.css. Qt has no priority system,
so instead the stylesheet carries `@{token}` placeholders that are substituted
here from one of two palettes. Light and dark stay one file that cannot drift.

As in the original, a missing or broken stylesheet must never stop the app
starting: the app is fully usable unstyled, and a colour is not worth a crash.
"""

import os
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

APP_NAME = "Windows Firewall & Hardening"
ORG_NAME = "win-harden"
STYLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "style.qss")

LIGHT = {
    "bg": "#f3f3f3", "navBg": "#eaeaea", "cardBg": "#ffffff",
    "fg": "#1b1b1b", "dim": "#5d5d5d", "disabled": "#a0a0a0",
    "border": "#d6d6d6", "borderSoft": "#ebebeb",
    "hover": "#00000010", "selected": "#00000018",
    "accent": "#0067c0", "accentFg": "#ffffff",
    "ok": "#0f7b0f", "okBg": "#f1f8f1",
    "warn": "#9d5d00", "warnBg": "#fdf6ec",
    "bad": "#c42b1c", "badBg": "#fdf3f2",
}

DARK = {
    "bg": "#202020", "navBg": "#272727", "cardBg": "#2b2b2b",
    "fg": "#f0f0f0", "dim": "#a8a8a8", "disabled": "#6b6b6b",
    "border": "#3d3d3d", "borderSoft": "#343434",
    "hover": "#ffffff12", "selected": "#ffffff1f",
    "accent": "#4cc2ff", "accentFg": "#00243d",
    "ok": "#6ccb5f", "okBg": "#1e2a1c",
    "warn": "#fce100", "warnBg": "#2c2717",
    "bad": "#ff99a4", "badBg": "#2d1d1e",
}

_TOKEN = re.compile(r"@\{(\w+)\}")


def load_stylesheet(dark=False, path=STYLE_PATH):
    """Read style.qss and substitute the palette.

    An unknown token is left alone rather than raising: Qt ignores a rule it
    cannot parse, so one stale token costs one rule, not the whole stylesheet.
    """
    palette = DARK if dark else LIGHT
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return ""
    return _TOKEN.sub(lambda m: palette.get(m.group(1), m.group(0)), source)


def prefers_dark():
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is None:
        return False
    try:
        return scheme() == Qt.ColorScheme.Dark
    except Exception:  # noqa: BLE001 - an unreadable hint just means light
        return False


class WinHardenApplication(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName(APP_NAME)
        self.setOrganizationName(ORG_NAME)
        self.setApplicationDisplayName(APP_NAME)
        self._window = None
        self.apply_theme()

        hints = self.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda _scheme: self.apply_theme())

    def apply_theme(self):
        self.setStyleSheet(load_stylesheet(dark=prefers_dark()))

    def show_window(self):
        from .window import MainWindow  # noqa: PLC0415 - avoids an import cycle

        if self._window is None:
            self._window = MainWindow()
        self._window.show()
        self._window.raise_()
        return self._window
