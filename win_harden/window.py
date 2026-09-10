"""Main window: a Win11-style left navigation over a stack of pages.

The Fedora app used an `Adw.ViewSwitcher` across the top, which is the GNOME
idiom. The Windows idiom for this many pages is the left navigation pane that
Settings itself uses, so that is what this is -- six destinations,
placed where a Windows user looks for them.

Construction order matters and mirrors the original's `_on_firewalld_ready`: the
window shows a status page first, reads the machine, and only then builds the
pages. Nothing is built against assumed state, and a machine we cannot read
produces an explanatory page rather than an empty one.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .backend.broker_client import BrokerClient
from .backend.powershell import PowerShellRunner
from .backend.scanning import ScanClient
from .settings import AppSettings

# id, label, and the module:class that builds it. Kept as data so the nav and
# the stack cannot fall out of step with each other.
PAGES = (
    ("dashboard", "Dashboard", "Overview and panic mode"),
    ("firewall", "Firewall Rules", "What is allowed in, per profile"),
    ("networks", "Networks", "Public or private, and DNS"),
    ("protection", "Protection", "Defender, ASR and ransomware"),
    ("virus_scan", "Virus Scan", "Scan files, remove threats and monitor downloads"),
    ("hardening", "Hardening", "Exposure, credentials, DNS, TLS"),
    ("updates", "Updates", "Application versions and updates"),
)


class MainWindow(QMainWindow):
    def __init__(self, parent=None, settings=None, monitor=None, updater=None):
        super().__init__(parent)
        self.setWindowTitle("Windows Firewall & Hardening")
        self.resize(1040, 760)
        self.setMinimumSize(880, 600)

        self.settings = settings or AppSettings()
        self.monitor = monitor
        self.powershell = PowerShellRunner(self)
        self.broker = BrokerClient(self)
        self.scanner = ScanClient(self)
        self._owns_updater = updater is None
        if updater is None:
            from .backend.updates import UpdateManager
            updater = UpdateManager(self.settings, self, busy=lambda: self.broker.has_pending_changes)
        self.updater = updater
        self.keep_in_tray = False

        root = QWidget(self)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_nav())
        self.stack = QStackedWidget(root)
        self.stack.setObjectName("contentArea")
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(root)
        self._build_pages()
        self._restore_last_page()

    # -- chrome ---------------------------------------------------------------

    def _build_nav(self):
        panel = QWidget(self)
        panel.setObjectName("navPanel")
        panel.setFixedWidth(232)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(0)

        title = QLabel("Firewall &&\nHardening", panel)
        title.setObjectName("appTitle")
        subtitle = QLabel("This PC", panel)
        subtitle.setObjectName("appSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.nav = QListWidget(panel)
        self.nav.setFrameShape(QListWidget.NoFrame)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        for page_id, label, tooltip in PAGES:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, page_id)
            item.setToolTip(tooltip)
            self.nav.addItem(item)
        self.nav.currentRowChanged.connect(self._on_nav_changed)
        layout.addWidget(self.nav, 1)

        return panel

    def _build_pages(self):
        """Import each page lazily and individually.

        One page failing to import degrades to that page showing why, rather
        than to a window that will not open -- the same reasoning as
        `load_families()` on the broker side.
        """
        self.pages = {}
        for page_id, label, _tooltip in PAGES:
            try:
                page = self._construct_page(page_id)
            except Exception as e:  # noqa: BLE001 - one page must not sink the window
                page = _PagePlaceholder(label, f"This page could not be loaded: {e}")
            self.pages[page_id] = page
            self.stack.addWidget(page)

    def _construct_page(self, page_id):
        module = __import__(f"win_harden.pages.{page_id}", fromlist=[page_id])
        factory = getattr(module, "PAGE_CLASS", None)
        if factory is None:
            raise AttributeError(f"win_harden.pages.{page_id} defines no PAGE_CLASS")
        return factory(self)

    def _restore_last_page(self):
        wanted = self.settings.last_page
        for index, (page_id, _label, _tooltip) in enumerate(PAGES):
            if page_id == wanted:
                self.nav.setCurrentRow(index)
                return
        self.nav.setCurrentRow(0)

    def _on_nav_changed(self, row):
        if row < 0:
            return
        self.stack.setCurrentIndex(row)
        page_id = PAGES[row][0]
        self.settings.last_page = page_id
        page = self.pages.get(page_id)
        # Pages refresh when shown rather than on a timer: a Windows read costs a
        # process, and refreshing a page nobody is looking at buys nothing.
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    # -- shutdown -------------------------------------------------------------

    def closeEvent(self, event):
        """Tear down the worker thread and any in-flight reads.

        Without this, closing the window while a PowerShell read is running
        leaves an orphaned powershell.exe, and the broker's worker thread keeps
        the process alive with no window to show for it.
        """
        if self.keep_in_tray:
            self.hide()
            event.ignore()
            return
        self.shutdown()
        super().closeEvent(event)

    def shutdown(self):
        if self._owns_updater:
            self.updater.shutdown()
        self.powershell.shutdown()
        self.broker.shutdown()
        self.scanner.shutdown()


class _PagePlaceholder(QWidget):
    """Shown in place of a page that could not be built."""

    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(8)
        heading = QLabel(title, self)
        heading.setObjectName("pageTitle")
        body = QLabel(message, self)
        body.setObjectName("pageSubtitle")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)
        layout.addStretch(1)
