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

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QStyle
from .version import VERSION

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
    notification = Signal(str, str)
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName(APP_NAME)
        self.setOrganizationName(ORG_NAME)
        self.setApplicationDisplayName(APP_NAME)
        self.setApplicationVersion(VERSION)
        self._window = None
        self.monitor = None
        self.tray = None
        self._server = None
        self.updater = None
        self.is_primary = self._single_instance('--background' not in argv)
        if not self.is_primary:
            return
        from .settings import AppSettings, config_dir
        from .downloads import DownloadMonitor
        self.settings = AppSettings()
        from .backend.updates import UpdateManager
        self.updater = UpdateManager(self.settings, self,
            busy=lambda: bool(self._window and self._window.broker.has_pending_changes))
        self.updater.available.connect(lambda version: self.notification.emit(
            "Application update available", f"Version {version} is ready. Open Updates to install it."))
        if os.name == 'nt':
            from scanner.paths import downloads_folder
            if not self.settings.downloads_initialized:
                try:
                    self.settings.watch_folders = [downloads_folder()]
                    self.settings.downloads_initialized = True
                except OSError:
                    pass
        self.monitor = DownloadMonitor(os.path.join(config_dir(), 'downloads.sqlite3'),
                                       self.settings.watch_folders, notify=self.notification.emit)
        if os.name == 'nt':
            self.monitor.start()
        self.aboutToQuit.connect(self.shutdown)
        self.commitDataRequest.connect(self._prepare_session_shutdown)
        self.apply_theme()

        hints = self.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda _scheme: self.apply_theme())

    def _single_instance(self, show):
        from PySide6.QtNetwork import QLocalServer, QLocalSocket
        from PySide6.QtCore import QLockFile
        from .settings import config_dir
        import hashlib
        os.makedirs(config_dir(), exist_ok=True)
        self._instance_lock = QLockFile(os.path.join(config_dir(), 'instance.lock'))
        name = 'win-harden-' + hashlib.sha256(config_dir().encode()).hexdigest()[:24]
        if not self._instance_lock.tryLock(0):
            socket = QLocalSocket(self)
            socket.connectToServer(name)
            if socket.waitForConnected(2000):
                socket.write(b'show' if show else b'background')
                socket.waitForBytesWritten(1000)
                socket.disconnectFromServer()
            return False
        QLocalServer.removeServer(name)
        self._server = QLocalServer(self)
        self._server.setSocketOptions(QLocalServer.UserAccessOption)
        self._server.listen(name)
        def connected():
            socket = self._server.nextPendingConnection()
            def ready():
                if bytes(socket.readAll()) == b'show':
                    self.show_window()
                socket.disconnectFromServer()
                socket.deleteLater()
            socket.readyRead.connect(ready)
            if socket.bytesAvailable():
                ready()
        self._server.newConnection.connect(connected)
        return True

    def start(self, background=False):
        self.show_window(hidden=background)
        if os.name == 'nt' and QSystemTrayIcon.isSystemTrayAvailable():
            self.setQuitOnLastWindowClosed(False)
            self.tray = QSystemTrayIcon(self.style().standardIcon(QStyle.SP_ComputerIcon), self)
            self.tray.setToolTip(APP_NAME + ' — download monitoring')
            menu = QMenu()
            menu.addAction('Open', self.show_window)
            menu.addAction('Check for application updates', self.show_updates)
            pause = menu.addAction('Pause additional download scans')
            pause.setCheckable(True)
            pause.toggled.connect(lambda checked: setattr(self.monitor, 'paused', checked))
            menu.addAction('Exit monitor', self.quit)
            self.tray.setContextMenu(menu)
            self._tray_menu = menu
            self.tray.activated.connect(lambda reason: self.show_window() if reason == QSystemTrayIcon.DoubleClick else None)
            self.notification.connect(lambda title, message: self.tray.showMessage(title, message))
            self.tray.show()
            self._window.keep_in_tray = True
        elif background:
            self.show_window()
        self.updater.start()

    def show_updates(self):
        window = self.show_window()
        from .window import PAGES
        window.nav.setCurrentRow(next(i for i, page in enumerate(PAGES) if page[0] == 'updates'))
        self.updater.check()

    def _prepare_session_shutdown(self, session):
        # Restart Manager uses session shutdown messages. A tray close alone
        # would leave the runtime locked. Do not interrupt a registry mutation.
        if self._window and self._window.broker.has_pending_changes:
            session.cancel()
            return
        if self._window:
            self._window.keep_in_tray = False
        self.shutdown()
        self.quit()

    def apply_theme(self):
        dark = prefers_dark()
        # Custom-painted switches cannot read QSS tokens back from Qt. Publish
        # the selected palette explicitly so they repaint with the same light or
        # dark semantic colours as the rest of the application.
        self.setProperty("winHardenDarkTheme", dark)
        self.setStyleSheet(load_stylesheet(dark=dark))
        for widget in self.allWidgets():
            if widget.objectName() == "stateSwitch":
                widget.update()

    def show_window(self, hidden=False):
        from .window import MainWindow  # noqa: PLC0415 - avoids an import cycle

        if self._window is None:
            self._window = MainWindow(settings=self.settings, monitor=self.monitor, updater=self.updater)
        if not hidden:
            self._window.showNormal()
            self._window.raise_()
            self._window.activateWindow()
        return self._window

    def shutdown(self):
        if self.updater:
            self.updater.shutdown()
        if self.monitor:
            self.monitor.stop()
        if self._window:
            self._window.shutdown()
        if self._server:
            self._server.close()
        if getattr(self, '_instance_lock', None):
            self._instance_lock.unlock()
