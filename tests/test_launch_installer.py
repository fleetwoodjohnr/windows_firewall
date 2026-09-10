"""The staged installer is rechecked, locked, and opened without elevation.

The pywin32 imports in launch_installer are function-local, so the real
function can be driven on any platform with the modules stubbed.
"""
import hashlib
import sys
import types

import pytest

from win_harden.updates import InstallerProcess, UpdateError, launch_installer

PAYLOAD = b'MZ-staged-installer'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FakeHandle:
    def __init__(self):
        self.closed = False

    def Close(self):
        self.closed = True


@pytest.fixture
def win32(monkeypatch):
    calls = types.SimpleNamespace(created=None, executed=None, handle=FakeHandle(), process=FakeHandle())

    con = types.SimpleNamespace(GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000,
                                FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, FILE_SHARE_DELETE=4,
                                OPEN_EXISTING=3, SW_SHOWNORMAL=1, STILL_ACTIVE=259)

    def create_file(path, access, share, security, disposition, flags, template):
        calls.created = dict(path=path, access=access, share=share, disposition=disposition)
        return calls.handle

    def shell_execute(**kwargs):
        calls.executed = kwargs
        return {'hProcess': calls.process}

    monkeypatch.setitem(sys.modules, 'win32con', con)
    monkeypatch.setitem(sys.modules, 'win32file', types.SimpleNamespace(CreateFile=create_file))
    monkeypatch.setitem(sys.modules, 'win32process',
                        types.SimpleNamespace(GetExitCodeProcess=lambda h: calls.exit_code))
    shell_mod = types.SimpleNamespace(shell=types.SimpleNamespace(ShellExecuteEx=shell_execute),
                                      shellcon=types.SimpleNamespace(SEE_MASK_NOCLOSEPROCESS=0x40))
    win32com = types.ModuleType('win32com')
    win32com.shell = shell_mod
    monkeypatch.setitem(sys.modules, 'win32com', win32com)
    monkeypatch.setitem(sys.modules, 'win32com.shell', shell_mod)
    calls.con = con
    return calls


@pytest.fixture
def staged(tmp_path):
    path = tmp_path / 'WinHardenSetup-1.3.0.exe'
    path.write_bytes(PAYLOAD)
    return path


def test_setup_is_opened_unelevated_without_restarting(win32, staged):
    process = launch_installer(staged, DIGEST)
    # 'runas' would lose Inno's original user and could relaunch the GUI elevated.
    assert win32.executed['lpVerb'] == 'open'
    assert win32.executed['lpParameters'] == '/NORESTART'
    assert win32.executed['lpFile'] == str(staged.resolve())
    assert isinstance(process, InstallerProcess)


def test_the_file_is_locked_against_writes_and_deletion(win32, staged):
    launch_installer(staged, DIGEST)
    created = win32.created
    assert created['access'] == win32.con.GENERIC_READ
    # Sharing reads only: nothing may write to or delete it while setup starts.
    assert created['share'] == win32.con.FILE_SHARE_READ
    assert created['disposition'] == win32.con.OPEN_EXISTING


def test_a_file_changed_after_verification_never_runs(win32, staged):
    staged.write_bytes(b'MZ-something-else-entirely')
    with pytest.raises(UpdateError, match='changed after verification'):
        launch_installer(staged, DIGEST)
    assert win32.executed is None
    assert win32.handle.closed


def test_the_handle_is_released_on_success(win32, staged):
    launch_installer(staged, DIGEST)
    assert win32.handle.closed


def test_a_missing_process_handle_is_an_error(win32, staged):
    win32.process = None
    with pytest.raises(UpdateError, match='did not return an installer process'):
        launch_installer(staged, DIGEST)
    assert win32.handle.closed


def test_a_running_setup_reports_no_exit_code(win32, staged):
    win32.exit_code = win32.con.STILL_ACTIVE
    assert launch_installer(staged, DIGEST).poll() is None


def test_a_finished_setup_reports_its_exit_code(win32, staged):
    win32.exit_code = 0
    process = launch_installer(staged, DIGEST)
    assert process.poll() == 0
    process.close()
    assert win32.process.closed
