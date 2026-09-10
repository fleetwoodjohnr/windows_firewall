"""Scan authorization, durable jobs and download lifecycle, without a live AV."""
import json
import uuid
from pathlib import Path

import pytest

from scanner.engine import classify, fingerprint
from scanner.jobs import Jobs
from scanner.protocol import MAX_FRAME, decode, encode, local_path, validate
from win_harden.downloads import DownloadMonitor


def request(kind='quick', **fields):
    return dict(version=1, op='submit', kind=kind, request_id=str(uuid.uuid4()), **fields)


@pytest.mark.parametrize('path', [r'\\server\share\file', r'\\?\C:\file', r'C:file',
    r'C:\file:stream', r'C:\a\..\b', r'C:\NUL.txt', r'C:\a.\b', r'C:\a?b',
    'C:\\bad\nfile', '/tmp/file', r'C:\a";whoami', 'C:\\' + 'a' * 240])
def test_custom_path_refuses_ambiguous_or_remote_names(path):
    with pytest.raises(ValueError):
        validate(request('custom', path=path))


def test_literal_filename_metacharacters_are_data():
    path = r"C:\Users\Zoë\Downloads\a [1] $thing `literal'.txt"
    assert validate(request('custom', path=path))['path'] == path
    assert local_path('C:/Downloads/a.txt') == r'C:\Downloads\a.txt'


@pytest.mark.parametrize('fields', [dict(command='whoami'), dict(kind='shell'),
    dict(version=999), dict(path=r'C:\x'), dict(request_id='not-a-uuid')])
def test_scan_protocol_has_no_generic_execution(fields):
    payload = request()
    payload.update(fields)
    with pytest.raises((ValueError, TypeError)):
        validate(payload)


def test_scan_protocol_bounded_and_roundtrips_unicode():
    payload = request('custom', path=r'C:\Users\Zoë\下载.txt')
    assert decode(encode(payload)) == payload
    with pytest.raises(ValueError):
        decode(b' ' * (MAX_FRAME + 1))
    with pytest.raises(ValueError):
        encode({'data': 'a' * MAX_FRAME})


@pytest.mark.parametrize('result,state', [
    ({}, 'failed'),
    ({'exitCode': 0}, 'incomplete'),
    ({'exitCode': 0, 'scanCompleted': True}, 'clean'),
    ({'exitCode': 0, 'scanCompleted': True, 'excluded': True}, 'incomplete'),
    ({'exitCode': 2, 'scanCompleted': True}, 'failed'),
    ({'exitCode': 0, 'scanCompleted': True, 'error': 'unreadable'}, 'failed'),
    ({'exitCode': 0, 'scanCompleted': True, 'threats': [{'active': True}]}, 'action_required'),
    ({'exitCode': 0, 'scanCompleted': True, 'threats': [{'active': False, 'actionSuccess': True}]}, 'remediated'),
    ({'exitCode': 0, 'threats': [{'active': False, 'actionSuccess': True}]}, 'incomplete'),
])
def test_scan_results_never_infer_clean_from_exit_code_alone(result, state):
    assert classify(result)['state'] == state


def test_changed_or_disappeared_file_is_not_clean(tmp_path):
    target = tmp_path / 'file'
    target.write_bytes(b'first')
    before = fingerprint(target)
    target.write_bytes(b'other')
    after = fingerprint(target)
    success = dict(exitCode=0, scanCompleted=True)
    assert classify(success, before, after)['state'] == 'incomplete'
    assert classify(success, before, None)['state'] == 'incomplete'
    assert classify(success, before, before)['fingerprint']['sha256'] == before['sha256']


class Engine:
    def __init__(self):
        self.calls = []
        self.fail = False

    def run(self, kind, path):
        self.calls.append((kind, path))
        if self.fail:
            raise RuntimeError('Defender unavailable')
        return {'state': 'clean', 'message': 'No threats detected'}

    def stop(self):
        pass


@pytest.fixture
def jobs(tmp_path):
    instance = Jobs(tmp_path / 'jobs.sqlite3', Engine())
    yield instance
    instance.stop()


def test_jobs_are_idempotent_and_private(jobs):
    request_id = str(uuid.uuid4())
    first = jobs.submit('alice', 'quick', request_id)
    assert jobs.submit('alice', 'quick', request_id)['id'] == first['id']
    with pytest.raises(ValueError):
        jobs.submit('alice', 'full', request_id)
    with pytest.raises(ValueError):
        jobs.get('bob', first['id'])
    with pytest.raises(ValueError):
        jobs.cancel('bob', first['id'])
    assert jobs.history('bob') == []
    assert jobs.run_one()
    assert jobs.get('alice', first['id'])['state'] == 'clean'
    assert not jobs.run_one()
    assert jobs.engine.calls == [('quick', '')]


def test_queued_cancel_and_failures(jobs):
    first = jobs.submit('alice', 'quick', str(uuid.uuid4()))
    jobs.cancel('alice', first['id'])
    assert not jobs.run_one()
    second = jobs.submit('alice', 'full', str(uuid.uuid4()))
    jobs.engine.fail = True
    jobs.run_one()
    result = jobs.get('alice', second['id'])
    assert result['state'] == 'failed'
    assert 'unavailable' in result['result']['message']


def test_restart_does_not_replay_custom_paths_as_system(tmp_path):
    path = tmp_path / 'jobs.sqlite3'
    first = Jobs(path, Engine())
    custom = first.submit('alice', 'custom', str(uuid.uuid4()), r'C:\Downloads\file')
    running = first.submit('alice', 'quick', str(uuid.uuid4()))
    first._finish(running['id'], 'running', {})
    resumable = first.submit('alice', 'full', str(uuid.uuid4()))
    first.stop()
    second = Jobs(path, Engine())
    try:
        assert second.get('alice', custom['id'])['state'] == 'incomplete'
        assert second.get('alice', running['id'])['state'] == 'incomplete'
        assert second.get('alice', resumable['id'])['state'] == 'queued'
        second.run_one()
        assert second.engine.calls == [('full', '')]
    finally:
        second.stop()


def test_authorization_scope_held_until_execution(jobs):
    events = []
    class Scope:
        def __enter__(self):
            events.append('authorized')
        def __exit__(self, *_):
            events.append('released')
        def close(self):
            events.append('closed')
    jobs.submit('alice', 'custom', str(uuid.uuid4()), 'file', Scope())
    assert not events
    jobs.run_one()
    assert events == ['authorized', 'released']
    item = jobs.submit('alice', 'custom', str(uuid.uuid4()), 'other', Scope())
    jobs.cancel('alice', item['id'])
    assert events[-1] == 'closed'


class Scanner:
    def __init__(self):
        self.calls, self.records = [], {}
        self.offline = False
    def submit(self, kind, path, request_id):
        self.calls.append((kind, path, request_id))
        self.records.setdefault(request_id, {'id': request_id, 'state': 'queued', 'result': {}})
        if self.offline:
            raise ConnectionError('Service unavailable')
        return self.records[request_id]
    def request(self, op, job_id):
        return self.records[job_id]


@pytest.fixture
def monitor(tmp_path):
    root = tmp_path / 'Downloads'
    root.mkdir()
    scanner = Scanner()
    monitor = DownloadMonitor(tmp_path / 'monitor.sqlite3', [str(root)], scanner.submit, scanner.request)
    monitor.connect()
    yield monitor, root, scanner
    monitor.db.close()


def test_partial_rename_settling_and_rewrite_rescan(monitor):
    monitor, root, scanner = monitor
    path = root / 'file.crdownload'
    path.write_text('hello')
    monitor.reconcile(0)
    monitor.process(10)
    assert not scanner.calls
    final = path.rename(root / 'file.txt')
    monitor.reconcile(11)
    monitor.process(12)
    assert not scanner.calls
    monitor.process(15)
    assert len(scanner.calls) == 1
    scan_id = scanner.calls[0][2]
    scanner.records[scan_id]['state'] = 'clean'
    monitor.process(16)
    monitor.reconcile(17)
    monitor.process(20)
    assert len(scanner.calls) == 1
    assert not monitor.db.execute("SELECT * FROM files WHERE state='downloading'").fetchall()
    final.write_text('changed content')
    monitor.reconcile(21)
    monitor.process(25)
    assert len(scanner.calls) == 2
    assert scanner.calls[1][2] != scan_id


def test_transport_retry_keeps_id_but_failed_scan_gets_new_id(monitor):
    monitor, root, scanner = monitor
    (root / 'file').write_text('test')
    monitor.reconcile(0)
    scanner.offline = True
    monitor.process(5)
    scanner.offline = False
    monitor.process(70)
    assert scanner.calls[0][2] == scanner.calls[1][2]
    key = scanner.calls[1][2]
    scanner.records[key]['state'] = 'failed'
    monitor.process(71)
    monitor.process(132)
    assert scanner.calls[-1][2] != key


def test_excluded_file_does_not_retry_forever(monitor):
    monitor, root, scanner = monitor
    (root / 'file').write_text('test')
    monitor.reconcile(0)
    monitor.process(5)
    key = scanner.calls[0][2]
    scanner.records[key].update(state='incomplete', result={'excluded': True})
    monitor.process(10)
    monitor.process(1000)
    assert len(scanner.calls) == 1
    assert monitor.db.execute('SELECT state FROM files').fetchone()[0] == 'incomplete'


def test_monitor_restart_keeps_job_and_rescan_folder_is_explicit(monitor):
    monitor, root, scanner = monitor
    (root / 'file').write_text('test')
    monitor.reconcile(0)
    monitor.process(5)
    key = scanner.calls[0][2]
    monitor.db.close()
    monitor.connect()
    scanner.records[key]['state'] = 'clean'
    monitor.reconcile(10)
    monitor.process(15)
    assert len(scanner.calls) == 1
    monitor.enqueue_folder(root)
    monitor.reconcile(20)
    monitor.process(25)
    assert len(scanner.calls) == 2


def test_no_traversal_of_linked_downloads(monitor, tmp_path):
    monitor, root, scanner = monitor
    other = tmp_path / 'elsewhere'
    other.mkdir()
    (other / 'secret').write_text('test')
    try:
        (root / 'link').symlink_to(other, target_is_directory=True)
    except OSError:
        pytest.skip('Creating symlinks requires Windows Developer Mode or elevation')
    monitor.reconcile(0)
    monitor.process(10)
    assert not scanner.calls
    assert monitor.errors


def test_quarantined_file_still_reports_remediation(monitor):
    monitor, root, scanner = monitor
    notices = []
    monitor.notify = lambda *args: notices.append(args)
    path = root / 'file'
    path.write_text('test')
    monitor.reconcile(0)
    monitor.process(5)
    key = scanner.calls[0][2]
    path.unlink()
    scanner.records[key].update(state='remediated', result={'message': 'Quarantined'})
    monitor.process(10)
    assert monitor.db.execute('SELECT state FROM files').fetchone()[0] == 'remediated'
    assert notices
