"""Asynchronous PowerShell runner for the GUI's unelevated reads.

The Fedora application uses an asynchronous subprocess API for status reads.
On Windows, Qt's Python bindings do not expose the native process modifier that
is needed to pass ``CREATE_NO_WINDOW``. A short-lived Python worker thread is
therefore used for each read. The thread waits for ``subprocess.Popen`` while
the Qt main loop remains responsive, and completion is marshalled back to the
GUI thread through a queued Qt signal.

This runs only the read-only scripts. Every write goes to the broker, and
``psinvoke.is_read_only`` is checked here rather than assumed, so a write script
cannot be run unelevated by mistake and silently half-succeed.
"""

import json
import subprocess
import threading

from PySide6.QtCore import QObject, Qt, Signal, Slot

from broker.psinvoke import InvocationError, build_argv, is_read_only
from broker.winprocess import creation_flags

from .errors import PowerShellError, PowerShellNotFound, translate_powershell_error

# Reads are quick. This is a backstop against a wedged WMI provider, which is a
# real and well-known way for Get-NetFirewallRule to hang forever.
READ_TIMEOUT_SECONDS = 60


class _ReadCall:
    """Thread-safe ownership of one child process.

    ``cancel`` may run on the Qt thread while ``execute`` is starting or waiting
    on the worker thread. The lock closes the small race where shutdown begins
    just before Popen publishes the new process handle.
    """

    def __init__(self, argv, script):
        self.argv = argv
        self.script = script
        self.thread = None
        self._lock = threading.Lock()
        self._process = None
        self._cancelled = False

    def publish_process(self, process):
        with self._lock:
            self._process = process
            cancelled = self._cancelled
        if cancelled:
            _kill(process)

    def clear_process(self, process):
        with self._lock:
            if self._process is process:
                self._process = None

    def cancel(self):
        with self._lock:
            self._cancelled = True
            process = self._process
        if process is not None:
            _kill(process)

    @property
    def cancelled(self):
        with self._lock:
            return self._cancelled


def _kill(process):
    """Best-effort termination used by timeout and application shutdown."""
    try:
        if process.poll() is None:
            process.kill()
    except (OSError, ProcessLookupError):
        # The child may exit between poll() and kill(). That is completion, not
        # a new user-facing failure.
        pass


def _run_read(call, timeout=READ_TIMEOUT_SECONDS, popen_factory=subprocess.Popen):
    """Run one already-validated read and return ``(result, error)``.

    Kept separate from the Qt orchestration so process creation, parsing,
    timeout handling, and the no-console flag can be exercised directly.
    """
    if call.cancelled:
        return None, PowerShellError("the application is closing")

    try:
        process = popen_factory(
            call.argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            shell=False,
            creationflags=creation_flags(),
        )
    except (FileNotFoundError, OSError) as e:
        return None, PowerShellNotFound(f"couldn't run powershell.exe: {e}")

    call.publish_process(process)
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(process)
            # Reap the process and close its pipe handles after termination.
            process.communicate()
            return None, PowerShellError(
                f"{call.script} didn't finish within {timeout} seconds")
    finally:
        call.clear_process(process)

    if call.cancelled:
        return None, PowerShellError("the application is closing")
    if process.returncode != 0:
        return None, translate_powershell_error(
            process.returncode, (stderr or stdout or "").strip())

    text = (stdout or "").strip()
    if not text:
        return {}, None
    try:
        parsed = json.loads(text)
    except ValueError as e:
        return None, PowerShellError(
            f"{call.script} produced output that isn't JSON: {e}")
    return (parsed if isinstance(parsed, dict) else {"items": parsed}), None


class PowerShellRunner(QObject):
    """Run concurrent status reads without blocking or opening a console."""

    _completed = Signal(int, object, object)

    def __init__(self, parent=None, script_root=None):
        super().__init__(parent)
        self._script_root = script_root
        self._running = {}
        self._next_token = 1
        # Force queuing even though the signal belongs to this QObject: it is
        # emitted by Python worker threads, while callbacks update Qt widgets.
        self._completed.connect(self._on_completed, Qt.ConnectionType.QueuedConnection)

    def run(self, script, params=None, callback=None):
        """Call ``callback(result, error)`` on the Qt thread when the read ends."""
        callback = callback or (lambda *_args: None)

        if not is_read_only(script):
            callback(None, PowerShellError(
                f"{script} changes the system, so it must go through the privileged "
                f"helper rather than being run here"
            ))
            return

        try:
            argv = build_argv(script, params, script_root=self._script_root)
        except InvocationError as e:
            callback(None, PowerShellError(str(e)))
            return

        token = self._next_token
        self._next_token += 1
        call = _ReadCall(argv, script)
        thread = threading.Thread(
            target=self._execute,
            args=(token, call),
            name=f"win-harden-read-{token}",
            daemon=True,
        )
        call.thread = thread
        self._running[token] = (call, callback)
        thread.start()

    def _execute(self, token, call):
        result, error = _run_read(call)
        try:
            self._completed.emit(token, result, error)
        except RuntimeError:
            # A daemon worker may outlive the one-second shutdown grace period
            # only if Windows itself is wedged. The QObject can be gone then;
            # there is no window left to receive this result.
            pass

    @Slot(int, object, object)
    def _on_completed(self, token, result, error):
        record = self._running.pop(token, None)
        if record is None:
            # Shutdown already completed this callback while the worker was
            # unwinding its killed child process.
            return
        _call, callback = record
        callback(result, error)

    def shutdown(self):
        """Stop child processes and complete every outstanding callback once."""
        records = list(self._running.values())
        self._running.clear()

        for call, _callback in records:
            call.cancel()
        for _call, callback in records:
            callback(None, PowerShellError("the application is closing"))
        for call, _callback in records:
            # kill() makes communicate() return promptly. Keep this wait bounded
            # so a broken OS process provider can never trap application exit.
            call.thread.join(timeout=1.0)
