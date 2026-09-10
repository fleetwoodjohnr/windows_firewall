"""The GUI's threaded, no-console PowerShell read path."""

import subprocess
import threading
import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from broker.winprocess import creation_flags
import win_harden.backend.powershell as gui_powershell
from win_harden.backend.errors import PowerShellError, PowerShellNotFound
from win_harden.backend.powershell import PowerShellRunner, _ReadCall, _run_read


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


class FakeProcess:
    def __init__(self, stdout="", stderr="", returncode=0, times_out=False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.times_out = times_out
        self.killed = False
        self.communications = 0

    def communicate(self, timeout=None):
        self.communications += 1
        if self.times_out and self.communications == 1:
            raise subprocess.TimeoutExpired("powershell.exe", timeout)
        return self.stdout, self.stderr

    def poll(self):
        if self.killed:
            return -9
        return None if self.times_out else self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def run_fake(process):
    captured = {}

    def factory(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return process

    call = _ReadCall(["powershell.exe", "-File", "status.ps1"], "status.ps1")
    result, error = _run_read(call, timeout=2, popen_factory=factory)
    return result, error, captured


def test_read_uses_no_shell_empty_stdin_and_platform_console_flags():
    result, error, options = run_fake(FakeProcess('{"enabled": true}'))
    assert result == {"enabled": True}
    assert error is None
    assert options["shell"] is False
    assert options["stdin"] is subprocess.DEVNULL
    assert options["creationflags"] == creation_flags()
    assert options["encoding"] == "utf-8-sig"


def test_array_output_is_normalised_for_page_consumers():
    result, error, _options = run_fake(FakeProcess('[{"name": "one"}]'))
    assert result == {"items": [{"name": "one"}]}
    assert error is None


def test_bad_json_and_nonzero_exit_are_user_facing_errors():
    result, error, _options = run_fake(FakeProcess("not json"))
    assert result is None
    assert isinstance(error, PowerShellError)
    assert "isn't JSON" in str(error)

    result, error, _options = run_fake(FakeProcess(stderr="query failed", returncode=5))
    assert result is None
    assert isinstance(error, PowerShellError)
    assert str(error) == "query failed"


def test_timeout_kills_and_reaps_the_hidden_child():
    process = FakeProcess(times_out=True)
    result, error, _options = run_fake(process)
    assert result is None
    assert isinstance(error, PowerShellError)
    assert "within 2 seconds" in str(error)
    assert process.killed
    assert process.communications == 2


def test_missing_powershell_and_pre_start_cancellation_do_not_escape():
    def missing(_argv, **_kwargs):
        raise FileNotFoundError("not installed")

    call = _ReadCall(["powershell.exe"], "status.ps1")
    result, error = _run_read(call, popen_factory=missing)
    assert result is None
    assert isinstance(error, PowerShellNotFound)

    called = []
    call = _ReadCall(["powershell.exe"], "status.ps1")
    call.cancel()
    result, error = _run_read(call, popen_factory=lambda *_a, **_kw: called.append(True))
    assert result is None
    assert isinstance(error, PowerShellError)
    assert called == []


def test_worker_completion_is_delivered_on_the_gui_thread(qapp, monkeypatch):
    worker_started = threading.Event()
    release_worker = threading.Event()

    def fake_read(_call):
        worker_started.set()
        release_worker.wait(2)
        return {"ready": True}, None

    monkeypatch.setattr(gui_powershell, "_run_read", fake_read)
    runner = PowerShellRunner(script_root="unused")
    callbacks = []
    runner.run(
        "status-firewall.ps1",
        callback=lambda result, error: callbacks.append(
            (result, error, threading.current_thread())))
    assert worker_started.wait(1), "the status worker never started"
    # The worker is still blocked, but the caller and Qt thread are responsive.
    assert callbacks == []
    release_worker.set()

    deadline = time.monotonic() + 2
    while not callbacks and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.005)

    assert callbacks == [({"ready": True}, None, threading.main_thread())]
    runner.shutdown()


def test_shutdown_completes_a_pending_callback_exactly_once(qapp, monkeypatch):
    worker_started = threading.Event()

    def wait_for_cancel(call):
        worker_started.set()
        deadline = time.monotonic() + 2
        while not call.cancelled and time.monotonic() < deadline:
            time.sleep(0.005)
        return None, PowerShellError("the application is closing")

    monkeypatch.setattr(gui_powershell, "_run_read", wait_for_cancel)
    runner = PowerShellRunner(script_root="unused")
    callbacks = []
    runner.run("status-firewall.ps1", callback=lambda *args: callbacks.append(args))
    assert worker_started.wait(1), "the status worker never started"
    runner.shutdown()
    qapp.processEvents()

    assert len(callbacks) == 1
    assert callbacks[0][0] is None
    assert "closing" in str(callbacks[0][1])
