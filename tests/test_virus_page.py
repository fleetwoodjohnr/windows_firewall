"""The antivirus UI reports evidence, queues work and confirms remediation."""
import pytest
pytest.importorskip('PySide6')
from PySide6.QtWidgets import QPushButton
from tests.test_pages import qapp, FakeWindow
from win_harden.pages.virus_scan import VirusScanPage
from win_harden.downloads import DownloadMonitor


class Client:
    def __init__(self):
        self.calls = []
        self.error = None
        self.jobs = []
    def call(self, op, callback):
        self.calls.append(op)
        if self.error:
            callback(None, self.error)
        elif op == 'health':
            callback(dict(available=True, realtimeProtection=True, downloadProtection=True,
                          signatureVersion='test', signatureAgeDays=0, activeThreats=0), None)
        else:
            callback({'jobs': self.jobs}, None)
    def submit(self, kind, callback, path):
        self.calls.append((kind, path))
        callback({'id': 'job', 'state': 'queued'}, None)


@pytest.fixture
def page(qapp, tmp_path):
    window = FakeWindow(tmp_path=tmp_path)
    window.scanner = Client()
    window.monitor = DownloadMonitor(tmp_path / 'monitor.db', [])
    page = VirusScanPage(window)
    yield page
    page.timer.stop()
    page.deleteLater()
    window.deleteLater()


def test_health_failures_clear_old_protection_values_and_recover(page):
    page.refresh()
    assert page.rows['realtime']._value.text() == 'On'
    page.client.error = RuntimeError('Service stopped')
    page.refresh()
    assert page.rows['engine']._value.text() == 'Unavailable'
    assert page.rows['realtime']._value.text() == 'Not verified'
    assert not page.busy
    page.client.error = None
    page.refresh()
    assert page.rows['realtime']._value.text() == 'On'
    assert not page.banner.showing


def test_buttons_queue_long_scans_without_reporting_completion(page):
    button = next(b for b in page.findChildren(QPushButton) if b.accessibleName() == 'Full scan')
    button.click()
    assert ('full', None) in page.client.calls
    assert page.banner._title.text() == 'Operation queued'
    assert page.table.rowCount() == 0


def test_history_does_not_turn_incomplete_into_clean(page):
    page.client.jobs = [dict(kind='custom', path=r'C:\file', state='incomplete', result={'message': 'File changed'})]
    page.refresh()
    assert page.table.item(0, 1).text() == 'Incomplete'
    assert page.table.item(0, 2).text() == 'File changed'


def test_removal_requires_explicit_confirmation_and_privileged_broker(page, monkeypatch):
    dialogs = []
    invoked = []
    monkeypatch.setattr('win_harden.pages.virus_scan.confirm', lambda *args: dialogs.append(args))
    page.window.broker.antivirus_action = lambda kind, callback: invoked.append(kind)
    page.remove_threats()
    assert not invoked
    assert 'ALL active threats' in dialogs[0][2]
    dialogs[0][4]()
    assert invoked == ['remediate']


def test_download_scanning_switch_controls_monitor_only(page):
    assert page.download_scanning.isChecked()
    page.download_scanning.setChecked(False)
    assert page.window.monitor.paused
    assert page.client.calls == []
