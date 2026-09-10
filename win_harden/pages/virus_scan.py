"""Scan, remediate, and monitor downloads through Microsoft Defender."""
from PySide6.QtCore import QTimer, QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QListWidget,
                               QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
                               QVBoxLayout, QWidget)

from ..widgets.page import Page, Group, Banner, KeyValueRow
from ..widgets.confirm import confirm
from ..widgets.state_switch import SwitchRow

LABELS = {'queued': 'Queued', 'running': 'Scanning', 'clean': 'No threats detected',
          'remediated': 'Threats remediated', 'action_required': 'Action required',
          'failed': 'Failed', 'incomplete': 'Incomplete', 'cancelled': 'Cancelled', 'completed': 'Completed'}


class _ActionRow(QWidget):
    """One scan action with enough context to choose it confidently."""

    def __init__(self, label, detail, button_label, action, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 6, 0, 6)
        layout.setSpacing(14)

        text = QVBoxLayout()
        text.setSpacing(2)
        title = QLabel(label, self)
        title.setObjectName('rowTitle')
        title.setWordWrap(True)
        text.addWidget(title)
        explanation = QLabel(detail, self)
        explanation.setObjectName('rowSubtitle')
        explanation.setWordWrap(True)
        text.addWidget(explanation)
        layout.addLayout(text, 1)

        button = QPushButton(button_label, self)
        button.setAccessibleName(label)
        button.setAccessibleDescription(detail)
        button.clicked.connect(action)
        layout.addWidget(button, 0, Qt.AlignVCenter)


class VirusScanPage(Page):
    def __init__(self, window):
        super().__init__('Virus Scan', 'Microsoft Defender scans and removes threats. Download monitoring adds scans to Windows real-time protection.')
        self.window = window
        self.client = window.scanner
        self.busy = False
        self.banner = self.add(Banner())
        group = self.add(Group('Protection status'))
        self.rows = {key: group.add(KeyValueRow(label)) for key, label in (
            ('engine', 'Antivirus'), ('realtime', 'Real-time protection'), ('downloads', 'Downloaded-file protection'),
            ('definitions', 'Definitions'), ('active', 'Active threats'), ('monitor', 'Download monitor'))}
        actions = self.add(Group('Scan this PC', 'Defender applies its configured quarantine/removal actions when a threat is found.'))
        for label, detail, button_label, action in [
            ('Quick scan', 'Checks the Windows locations where active malware is most likely to be running. Usually finishes fastest.', 'Start', lambda: self.submit('quick')),
            ('Full scan', 'Checks every file Defender can access on every attached drive. This can take hours and keeps running if this window is closed.', 'Start', lambda: self.submit('full')),
            ('Scan a file', 'Choose one local file and add it to the protected scanner service.', 'Choose file…', self.scan_file),
            ('Scan a folder', 'Queues each readable regular file below one local folder. Linked folders and unsupported paths are skipped and reported.', 'Choose folder…', self.scan_folder),
            ('Update definitions', 'Asks Microsoft Defender to download the newest malware definitions. Internet access may be required.', 'Update', lambda: self.submit('update')),
            ('Enable download protection', 'Turns on Defender checks for files downloaded from browsers and email. Windows may refuse this while Tamper Protection or organization policy controls it.', 'Enable', lambda: self.privileged('protect')),
            ('Remove active threats', 'Asks Defender to remediate every currently active threat using its configured quarantine or removal action.', 'Review and remove…', self.remove_threats),
            ('Windows Security and quarantine', 'Opens the Windows-owned protection history where quarantined items, required actions, and restart requests are reviewed.', 'Open', self.open_security),
        ]:
            actions.add(_ActionRow(label, detail, button_label, action, actions))
        monitor = self.add(Group('Automatic download scans', 'Downloads and the folders below are scanned in the background. Files can be opened while a rescan is pending.'))
        self.download_scanning = monitor.add(SwitchRow(
            'Additional download scanning',
            'On watches the folders below and queues stable new or changed files for Defender. Turning it off pauses these additional scans; Defender real-time protection continues independently.',
            checked=not bool(getattr(window.monitor, 'paused', False)),
        ))
        self.download_scanning.toggled.connect(self.set_download_scanning)
        self.folders = monitor.add(QListWidget())
        self.folders.setMaximumHeight(120)
        self.load_folders()
        add = monitor.add(QPushButton('Add watched folder…'))
        add.clicked.connect(self.add_folder)
        remove = monitor.add(QPushButton('Remove selected folder'))
        remove.clicked.connect(self.remove_folder)
        history = self.add(Group('Recent scans', 'Results describe the scanned content at that time; no antivirus can guarantee a file is safe. Select a row to see details.'))
        self.table = history.add(QTableWidget(0, 3))
        self.table.setHorizontalHeaderLabels(['Scan / file', 'Result', 'Details'])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setMinimumHeight(260)
        self.details = history.add(QLabel())
        self.details.setWordWrap(True)
        self.details.setTextFormat(Qt.PlainText)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.refresh() if self.isVisible() else None)
        self.timer.start(5000)

    def refresh(self):
        if self.busy:
            return
        self.busy = True
        monitor = getattr(self.window, 'monitor', None)
        self.rows['monitor'].set_value(monitor.status if monitor else 'Not running', 'warn' if not monitor or monitor.errors else None)
        self.client.call('health', self.on_health)

    def on_health(self, result, error):
        if error or not (result or {}).get('available'):
            self.banner.show_message('Antivirus needs attention', str(error or (result or {}).get('error', 'Defender is unavailable.')), 'error')
            self.rows['engine'].set_value('Unavailable', 'bad')
            for key in ('realtime', 'downloads', 'definitions', 'active'):
                self.rows[key].set_value('Not verified', 'warn')
        else:
            if self.banner._title.text() in ('Antivirus needs attention', 'Scan history unavailable'):
                self.banner.hide_message()
            self.rows['engine'].set_value('Microsoft Defender', 'ok')
            for key, field in [('realtime', 'realtimeProtection'), ('downloads', 'downloadProtection')]:
                enabled = result.get(field)
                self.rows[key].set_value('On' if enabled else 'Off', 'ok' if enabled else 'bad')
            age = result.get('signatureAgeDays')
            self.rows['definitions'].set_value(f"{result.get('signatureVersion', 'Unknown')} — {age} day(s) old", 'ok' if age is not None and age <= 2 else 'warn')
            self.rows['active'].set_value(result.get('activeThreats', 'Unknown'), 'bad' if result.get('activeThreats') else None)
        self.client.call('history', self.on_history)

    def on_history(self, result, error):
        self.busy = False
        if error:
            self.banner.show_message('Scan history unavailable', str(error), 'error')
            return
        jobs = (result or {}).get('jobs', [])
        self.table.setRowCount(len(jobs))
        for row, job in enumerate(jobs):
            detail = job.get('result') or {}
            message = detail.get('message', '')
            threats = detail.get('threats') or []
            if threats:
                message += '\n' + '\n'.join(t.get('name') or t.get('id', '') for t in threats)
            for col, text in enumerate((job.get('path') or job['kind'], LABELS.get(job['state'], job['state']), message)):
                item = QTableWidgetItem(str(text))
                item.setToolTip(str(text))
                self.table.setItem(row, col, item)

    def show_detail(self):
        row = self.table.currentRow()
        if row >= 0 and self.table.item(row, 2):
            self.details.setText(self.table.item(row, 2).text())

    def submitted(self, result, error):
        if error:
            self.banner.show_message('Operation could not start', str(error), 'error')
        else:
            self.banner.show_message('Operation queued', 'The result will appear in Recent scans. Closing the window keeps background protection running.')
        self.refresh()

    def submit(self, kind, path=None):
        self.client.submit(kind, self.submitted, path)

    def privileged(self, kind):
        self.window.broker.antivirus_action(kind, self.submitted)

    def remove_threats(self):
        confirm(self.window, 'Remove active threats',
                'Microsoft Defender will remediate ALL active threats it has detected on this PC using its configured actions. Review Windows Security for quarantine and any required restart.',
                'Remove active threats', lambda: self.privileged('remediate'))

    def scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Scan a file')
        if path:
            self.submit('custom', path)

    def scan_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Scan a folder')
        if path:
            from scanner.protocol import local_path
            try:
                path = local_path(path)
            except ValueError as exc:
                self.banner.show_message('Folder not supported', str(exc), 'warning')
                return
            self.window.monitor.enqueue_folder(path)
            self.banner.show_message('Folder queued', 'Each readable regular file will be scanned. Linked folders are skipped and reported by the monitor.')

    @staticmethod
    def open_security():
        QDesktopServices.openUrl(QUrl('windowsdefender://threat'))

    def set_download_scanning(self, enabled):
        self.window.monitor.paused = not enabled

    def load_folders(self):
        self.folders.clear()
        self.folders.addItems(self.window.settings.watch_folders)

    def add_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Watch a download folder')
        if path:
            from scanner.protocol import local_path
            try:
                path = local_path(path)
            except ValueError as exc:
                self.banner.show_message('Folder not supported', str(exc), 'warning')
                return
            roots = list(dict.fromkeys([*self.window.settings.watch_folders, path]))
            self.window.settings.watch_folders = roots
            self.window.monitor.set_roots(roots)
            self.load_folders()

    def remove_folder(self):
        item = self.folders.currentItem()
        if item:
            roots = [p for p in self.window.settings.watch_folders if p != item.text()]
            self.window.settings.watch_folders = roots
            self.window.monitor.set_roots(roots)
            self.load_folders()


PAGE_CLASS = VirusScanPage
