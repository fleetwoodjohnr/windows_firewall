"""Release trust, interrupted transfers, scheduling and the update UI."""
import hashlib
import json
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, QTimer, QUrl, Signal
from PySide6.QtNetwork import QNetworkReply, QNetworkRequest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from win_harden.backend.updates import HttpTransfer, UpdateManager
from win_harden.settings import AppSettings
from win_harden.updates import (CHECK_INTERVAL, LATEST_URL, REPOSITORY, RETRY_INTERVAL,
    InstallerDownload, UpdateError, allowed_download_url, parse_checksum,
    parse_release, version_tuple)

PAYLOAD = b'MZ-test-installer-content'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def release_data(version='1.3.0'):
    filename = f'WinHardenSetup-{version}.exe'
    return dict(tag_name='v' + version, draft=False, prerelease=False,
        body='Updates <b>remain plain text</b>.', assets=[
            dict(name=name, state='uploaded', size=size,
                 browser_download_url=f'https://github.com/{REPOSITORY}/releases/download/v{version}/{name}',
                 digest='sha256:' + DIGEST if name == filename else None)
            for name, size in [(filename, len(PAYLOAD)), (filename + '.sha256', 100)]])


def checksum_data(version='1.3.0'):
    return f'{DIGEST}  WinHardenSetup-{version}.exe\n'.encode()


@pytest.fixture(scope='module')
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize('version', ['1.10.0', '2.0.0', '1.3.0'])
def test_newer_versions_use_numeric_order(version):
    assert parse_release(release_data(version), '1.2.0').version == version
    assert version_tuple('1.10.0') > version_tuple('1.9.0')


@pytest.mark.parametrize('version', ['1.2.0', '1.1.9'])
def test_same_and_older_versions_are_not_offered(version):
    assert parse_release(release_data(version), '1.2.0') is None


@pytest.mark.parametrize('version', ['1.2', '1.2.3.4', 'v1.2.3', '1.2.3-beta', '01.2.3', '65536.0.0', None])
def test_invalid_version(version):
    with pytest.raises(UpdateError):
        version_tuple(version)


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(draft=True), lambda d: d.update(prerelease=True),
    lambda d: d.update(tag_name='main'), lambda d: d.update(assets=[]),
    lambda d: d['assets'].append(d['assets'][0]),
    lambda d: d['assets'][0].update(size=True),
    lambda d: d['assets'][0].update(size=2**40),
    lambda d: d['assets'][0].update(state='new'),
    lambda d: d['assets'][0].update(browser_download_url='https://evil.example/setup.exe'),
    lambda d: d['assets'][0].update(digest='sha256:bad'),
])
def test_incomplete_or_untrusted_releases_fail(mutate):
    data = release_data()
    mutate(data)
    with pytest.raises(UpdateError):
        parse_release(data, '1.2.0')


@pytest.mark.parametrize('url', ['http://github.com/x', 'https://github.com.evil.example/x',
    'https://user@release-assets.githubusercontent.com/x', 'https://release-assets.githubusercontent.com:444/x',
    'https://github.com/another/repo/releases/download/v1/setup.exe', 'file:///tmp/setup.exe',
    'https://release-assets.githubusercontent.com/x#fragment', 'https://evil.example/x'])
def test_redirect_allowlist(url):
    assert not allowed_download_url(url)


def test_github_asset_hosts_are_allowed():
    assert allowed_download_url(LATEST_URL)
    assert allowed_download_url('https://release-assets.githubusercontent.com/blob?sig=example')
    assert allowed_download_url(release_data()['assets'][0]['browser_download_url'])


@pytest.mark.parametrize('raw', [b'broken', b'\xff',
    (DIGEST + '  another.exe').encode(), ('0' * 64 + '  WinHardenSetup-1.3.0.exe').encode(),
    checksum_data() + checksum_data()])
def test_wrong_checksums_are_rejected(raw):
    with pytest.raises(UpdateError):
        parse_checksum(raw, parse_release(release_data(), '1.2.0'))


def test_checksum_and_staging(tmp_path):
    release = parse_release(release_data(), '1.2.0')
    assert parse_checksum(checksum_data(), release) == DIGEST
    stage = InstallerDownload(release, DIGEST, tmp_path)
    stage.write(PAYLOAD[:5])
    assert not stage.path.exists()
    stage.write(PAYLOAD[5:])
    assert stage.finish().read_bytes() == PAYLOAD
    assert not stage.partial.exists()
    stage.discard()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('payload', [PAYLOAD[:-1], b'x' * len(PAYLOAD), PAYLOAD + b'oversized'])
def test_invalid_download_never_becomes_executable(tmp_path, payload):
    stage = InstallerDownload(parse_release(release_data(), '1.2.0'), DIGEST, tmp_path)
    with pytest.raises(UpdateError):
        stage.write(payload)
        stage.finish()
    assert not stage.path.exists()
    stage.discard()
    assert list(tmp_path.iterdir()) == []


class FakeTransport:
    def __init__(self):
        self.requests = []

    def __call__(self, url, limit, done, chunk):
        request = SimpleNamespace(url=url, limit=limit, done=done, chunk=chunk, cancelled=False)
        def cancel():
            request.cancelled = True
            done(b'', 0, 'Cancelled.')
        request.cancel = cancel
        self.requests.append(request)
        return request

    def respond(self, raw=b'', status=200, error=None):
        request = self.requests[-1]
        if request.chunk and not error:
            try:
                request.chunk(raw)
            except (ValueError, OSError) as exc:
                error = str(exc)
        request.done(raw if not request.chunk else b'', status, error)


@pytest.fixture
def manager(qapp, tmp_path):
    transport = FakeTransport()
    launched = []
    manager = UpdateManager(AppSettings(str(tmp_path / 'settings.json')), transport=transport,
        launcher=lambda path, digest: launched.append((path, digest)), installed=True,
        clock=lambda: 1000000, cache=tmp_path / 'updates')
    manager.fake = transport
    manager.launched = launched
    yield manager
    manager.shutdown()


def offer_update(manager):
    manager.check()
    manager.fake.respond(json.dumps(release_data()).encode())
    assert manager.fake.requests[-1].url.endswith('.sha256')
    manager.fake.respond(checksum_data())
    assert manager.state == 'available'


def test_update_checks_then_downloads_then_launches(manager):
    notifications, starts = [], []
    manager.available.connect(notifications.append)
    manager.installer_started.connect(lambda: starts.append(True))
    offer_update(manager)
    assert notifications == ['1.3.0']
    assert not manager.launched
    manager.update()
    assert manager.state == 'downloading'
    manager.fake.respond(PAYLOAD)
    assert manager.state == 'launched'
    assert manager.launched[0][0].read_bytes() == PAYLOAD
    assert manager.launched[0][1] == DIGEST
    assert starts == [True]


def test_checks_are_daily_and_notifications_once_per_version(manager):
    notifications = []
    manager.available.connect(notifications.append)
    offer_update(manager)
    count = len(manager.fake.requests)
    manager.check_if_due()
    assert len(manager.fake.requests) == count
    offer_update(manager)  # manual checks ignore the daily timer
    assert notifications == ['1.3.0']
    manager.clock = lambda: 1000000 + CHECK_INTERVAL
    manager.check_if_due()
    assert manager.state == 'checking'


def test_disabled_automatic_checks_and_development_install(manager):
    manager.set_automatic(False)
    manager.check_if_due()
    assert not manager.fake.requests
    offer_update(manager)
    manager.installed = False
    manager.update()
    assert not manager.launched
    assert not manager.download


@pytest.mark.parametrize('status,error', [(404, 'missing'), (403, 'rate limited'), (0, 'TLS failure')])
def test_failed_check_does_not_claim_current_or_install(manager, status, error):
    manager.check()
    manager.fake.respond(status=status, error=error)
    assert manager.state == ('idle' if status == 404 else 'error')
    assert manager.settings.updates_last_checked == 0
    assert not manager.launched


def test_malformed_response_is_reported(manager):
    manager.check()
    manager.fake.respond(b'not json')
    assert manager.state == 'error'


def test_cancelled_download_ignores_late_completion(manager):
    offer_update(manager)
    manager.update()
    request = manager.fake.requests[-1]
    stage = manager.download
    request.chunk(PAYLOAD[:5])
    manager.cancel()
    request.done(b'', 200, None)
    assert request.cancelled
    assert not stage.directory.exists()
    assert not manager.launched


def test_security_change_defers_installer(manager):
    offer_update(manager)
    manager.security_busy = lambda: True
    manager.update()
    assert not manager.download
    manager.security_busy = lambda: False
    manager.update()
    manager.security_busy = lambda: True
    manager.fake.respond(PAYLOAD)
    assert manager.state == 'ready'
    assert not manager.launched
    manager.security_busy = lambda: False
    manager.update()
    assert manager.state == 'launched'


def test_uac_cancel_keeps_ready_download(manager):
    def cancelled(*args):
        exc = OSError('User cancelled')
        exc.winerror = 1223
        raise exc
    manager.launcher = cancelled
    offer_update(manager)
    manager.update()
    manager.fake.respond(PAYLOAD)
    assert manager.state == 'ready'
    assert manager.download.path.exists()


def test_cancelled_setup_leaves_app_available(manager):
    closed = []
    manager.launcher = lambda *_: SimpleNamespace(poll=lambda: 2, close=lambda: closed.append(True))
    offer_update(manager)
    manager.update()
    manager.fake.respond(PAYLOAD)
    manager._poll_setup()
    assert manager.state == 'available'
    assert manager.download is None
    assert closed == [True]


def test_bad_download_never_launches(manager):
    offer_update(manager)
    manager.update()
    manager.fake.respond(b'bad')
    assert manager.state == 'error'
    assert not manager.launched
    assert manager.download is None


def test_updates_page_behaviour(manager):
    from win_harden.pages.updates import UpdatesPage
    page = UpdatesPage(SimpleNamespace(updater=manager))
    assert page.check.isEnabled()
    assert not page.install.isEnabled()
    offer_update(manager)
    assert page.install.isEnabled()
    assert page.notes.text() == release_data()['body']
    manager.update()
    assert not page.check.isEnabled()
    assert not page.install.isEnabled()
    assert not page.cancel.isHidden()
    manager.cancel()
    assert page.check.isEnabled()
    page.deleteLater()


class Reply(QObject):
    readyRead = Signal()
    finished = Signal()

    def __init__(self, url, status, body=b'', redirect=None, error=QNetworkReply.NoError):
        super().__init__()
        self.location, self.status, self.body = url, status, body
        self.redirect, self.failure = redirect, error
        self.running = True

    def setReadBufferSize(self, _): pass
    def bytesAvailable(self): return len(self.body)
    def readAll(self): return self.read(len(self.body))
    def read(self, size):
        data, self.body = self.body[:size], self.body[size:]
        return data
    def isRunning(self): return self.running
    def error(self): return self.failure
    def errorString(self): return 'Network failure'
    def url(self): return QUrl(self.location)
    def attribute(self, name):
        if name == QNetworkRequest.HttpStatusCodeAttribute:
            return self.status
        if name == QNetworkRequest.RedirectionTargetAttribute:
            return QUrl(self.redirect) if self.redirect else None
    def abort(self):
        self.running = False
        self.finished.emit()
    def deliver(self):
        self.readyRead.emit()
        self.running = False
        self.finished.emit()


class Network:
    def __init__(self, responses):
        self.responses, self.urls, self.replies = list(responses), [], []
    def get(self, request):
        self.urls.append(request.url().toString())
        reply = Reply(self.urls[-1], **self.responses.pop(0))
        self.replies.append(reply)
        QTimer.singleShot(0, reply.deliver)
        return reply


@pytest.mark.parametrize('responses,limit,error', [
    ([dict(status=200, body=b'ok')], 10, False),
    ([dict(status=200, body=b'oversize')], 2, True),
    ([dict(status=302, redirect='https://evil.example/exe')], 10, True),
    ([dict(status=302, redirect='http://release-assets.githubusercontent.com/exe')], 10, True),
    ([dict(status=200, body=b'partial', error=QNetworkReply.RemoteHostClosedError)], 100, True),
    ([dict(status=403)], 10, True),
    ([dict(status=302, redirect='https://release-assets.githubusercontent.com/exe'), dict(status=200, body=b'ok')], 10, False),
])
def test_real_transfer_state_machine(qapp, responses, limit, error):
    network, results = Network(responses), []
    transfer = HttpTransfer(network, LATEST_URL, limit, lambda *args: results.append(args))
    QTest.qWait(30)
    assert len(results) == 1
    assert bool(results[0][2]) == error
    if not error:
        assert results[0][0] == b'ok'


def test_session_shutdown_waits_for_security_changes():
    from win_harden.application import WinHardenApplication
    events = []
    window = SimpleNamespace(broker=SimpleNamespace(has_pending_changes=True), keep_in_tray=True)
    app = SimpleNamespace(_window=window, shutdown=lambda: events.append('shutdown'), quit=lambda: events.append('quit'))
    session = SimpleNamespace(cancel=lambda: events.append('cancel'))
    WinHardenApplication._prepare_session_shutdown(app, session)
    assert events == ['cancel'] and window.keep_in_tray
    events.clear()
    window.broker.has_pending_changes = False
    WinHardenApplication._prepare_session_shutdown(app, session)
    assert events == ['shutdown', 'quit'] and not window.keep_in_tray


def test_timeout_completes_only_once(qapp):
    results = []
    network = Network([dict(status=200, body=b'ok')])
    transfer = HttpTransfer(network, LATEST_URL, 100, lambda *args: results.append(args))
    transfer.deadline.timeout.emit()
    QTest.qWait(30)
    assert len(results) == 1 and 'timed out' in results[0][2]


def test_download_write_failure_reports_error(manager, monkeypatch):
    offer_update(manager)
    manager.update()
    stage = manager.download
    def full(_):
        raise OSError('Disk full')
    monkeypatch.setattr(stage, 'write', full)
    manager.fake.respond(PAYLOAD)
    assert manager.state == 'error' and 'Disk full' in manager.message
    assert not stage.directory.exists() and not manager.launched


def test_a_failed_check_retries_sooner_than_a_successful_one(manager):
    manager.check()
    manager.fake.respond(status=403, error='rate limited')
    assert manager.state == 'error'
    count = len(manager.fake.requests)

    # The attempt was stamped before the request, so without the shorter
    # interval a rate limit or a dropped link would cost a whole day.
    manager.clock = lambda: 1000000 + RETRY_INTERVAL - 60
    manager.check_if_due()
    assert len(manager.fake.requests) == count

    manager.clock = lambda: 1000000 + RETRY_INTERVAL
    manager.check_if_due()
    assert len(manager.fake.requests) == count + 1


def test_a_successful_check_still_waits_a_full_day(manager):
    offer_update(manager)
    count = len(manager.fake.requests)
    manager.clock = lambda: 1000000 + RETRY_INTERVAL
    manager.check_if_due()
    assert len(manager.fake.requests) == count


def test_staging_directories_from_earlier_attempts_are_removed(manager, tmp_path):
    root = tmp_path / 'updates'
    root.mkdir(parents=True, exist_ok=True)
    stale = root / '1.2.5-abcdef'
    stale.mkdir()
    (stale / 'WinHardenSetup-1.2.5.exe').write_bytes(b'MZ-leftover')
    loose = root / 'not-a-directory'
    loose.write_bytes(b'')

    offer_update(manager)
    manager.update()
    assert not stale.exists()
    assert manager.download.directory.exists()
    assert loose.exists()


def test_startup_clears_an_installer_left_behind_by_a_completed_upgrade(manager, tmp_path):
    root = tmp_path / 'updates'
    root.mkdir(parents=True, exist_ok=True)
    orphan = root / '1.2.9-fedcba'
    orphan.mkdir()
    (orphan / 'WinHardenSetup-1.2.9.exe').write_bytes(b'MZ-left-by-setup')
    manager.start()
    assert not orphan.exists()
