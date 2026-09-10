"""Application updates, separate from Microsoft Defender definition updates."""

from datetime import datetime

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QLabel, QProgressBar, QPushButton

from ..updates import RELEASES_URL
from ..version import VERSION
from ..widgets.page import Page, Group, Banner, KeyValueRow


class UpdatesPage(Page):
    def __init__(self, window):
        super().__init__("Updates", "Get the latest improvements to Windows Firewall & Hardening.")
        self.manager = window.updater
        self.banner = self.add(Banner())
        version = self.add(Group("Application version"))
        version.add(KeyValueRow("Installed", VERSION))
        self.latest = version.add(KeyValueRow("Latest", "Not checked"))
        self.last_check = version.add(KeyValueRow("Last successful check", "Never"))
        self.automatic = version.add(QCheckBox("Check automatically and notify me about updates"))
        self.automatic.setChecked(self.manager.settings.check_updates_automatically)
        self.automatic.toggled.connect(self.manager.set_automatic)
        self.check = version.add(QPushButton("Check for updates"))
        self.check.clicked.connect(self.manager.check)
        self.install = version.add(QPushButton("Update"))
        self.install.clicked.connect(self.manager.update)
        self.progress_bar = version.add(QProgressBar())
        self.cancel = version.add(QPushButton("Cancel download"))
        self.cancel.clicked.connect(self.manager.cancel)
        note = version.add(QLabel("Updating opens an install wizard and requires administrator approval. The app and its download monitor close during installation. Existing settings and history are kept."))
        note.setWordWrap(True)
        notes = self.add(Group("What's new"))
        self.notes = notes.add(QLabel("Release notes will appear here when an update is available."))
        self.notes.setTextFormat(Qt.PlainText)
        self.notes.setWordWrap(True)
        self.notes.setTextInteractionFlags(Qt.TextSelectableByMouse)
        link = notes.add(QPushButton("View releases on GitHub"))
        link.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.manager.release.url if self.manager.release else RELEASES_URL)))
        self.manager.changed.connect(self.refresh)
        self.manager.progress.connect(self.on_progress)
        self.add_stretch()
        self.refresh()

    def refresh(self):
        manager = self.manager
        self.banner.show_message("Application update", manager.message, "error" if manager.state == "error" else "info")
        self.latest.set_value(manager.latest_version or "Not available")
        timestamp = manager.settings.updates_last_checked
        try:
            date = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M") if timestamp > 0 else "Never"
        except (ValueError, OSError, OverflowError):
            date = "Never"
        self.last_check.set_value(date)
        self.check.setEnabled(not manager.active and manager.state != "launched")
        self.install.setEnabled(bool(manager.installed and manager.release and manager.checksum and not manager.active and manager.state != "launched"))
        self.cancel.setVisible(manager.state == "downloading")
        self.progress_bar.setVisible(manager.state == "downloading")
        if manager.release:
            self.notes.setText(manager.release.notes)
        if not manager.installed:
            self.install.setToolTip("Updates can only be installed by the packaged Windows application.")

    def on_progress(self, received, total):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(int(received * 100 / total) if total else 0)


PAGE_CLASS = UpdatesPage
