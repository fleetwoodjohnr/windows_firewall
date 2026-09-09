"""Async PowerShell runner for the GUI's unelevated reads.

The direct counterpart of the Fedora app's `NetworkManagerClient._run`
(backend/networkmanager.py:52-80): an argv list, never a shell, run through the
toolkit's own subprocess type so nothing blocks the main loop. `Gio.Subprocess`
becomes `QProcess`; the callback shape is unchanged.

This runs only the read-only scripts. Every write goes to the broker, and
`psinvoke.is_read_only` is checked here rather than assumed, so a write script
cannot be run unelevated by mistake and silently half-succeed.
"""

import json

from PySide6.QtCore import QObject, QProcess

from broker.psinvoke import InvocationError, build_argv, is_read_only

from .errors import PowerShellError, PowerShellNotFound, translate_powershell_error

# Reads are quick. This is a backstop against a wedged WMI provider, which is a
# real and well-known way for Get-NetFirewallRule to hang forever.
READ_TIMEOUT_MS = 60_000


class PowerShellRunner(QObject):
    """One runner, many concurrent reads.

    Each call owns its QProcess and is parented to this object so that closing
    the window tears down anything still in flight rather than leaving orphaned
    powershell.exe processes behind.
    """

    def __init__(self, parent=None, script_root=None):
        super().__init__(parent)
        self._script_root = script_root
        self._running = []

    def run(self, script, params=None, callback=None):
        """callback(result: dict | None, error: WinHardenError | None)"""
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

        process = QProcess(self)
        self._running.append(process)

        # `finished` and the timeout are made mutually exclusive by this flag,
        # the same guard the broker client uses: a late timeout must not fire
        # after a completion, and vice versa.
        state = {"done": False}

        def finish(result, error):
            if state["done"]:
                return
            state["done"] = True
            if process in self._running:
                self._running.remove(process)
            process.deleteLater()
            callback(result, error)

        def on_finished(exit_code, _exit_status):
            stdout = bytes(process.readAllStandardOutput()).decode("utf-8", "replace")
            stderr = bytes(process.readAllStandardError()).decode("utf-8", "replace")
            if exit_code != 0:
                finish(None, translate_powershell_error(exit_code, stderr))
                return
            text = stdout.strip()
            if not text:
                finish({}, None)
                return
            try:
                parsed = json.loads(text)
            except ValueError as e:
                finish(None, PowerShellError(f"{script} produced output that isn't JSON: {e}"))
                return
            finish(parsed if isinstance(parsed, dict) else {"items": parsed}, None)

        def on_error(_error):
            finish(None, PowerShellNotFound(
                f"couldn't run powershell.exe: {process.errorString()}"
            ))

        process.finished.connect(on_finished)
        process.errorOccurred.connect(on_error)

        from PySide6.QtCore import QTimer  # noqa: PLC0415

        timer = QTimer(process)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: (process.kill(), finish(None, PowerShellError(
            f"{script} didn't finish within {READ_TIMEOUT_MS // 1000} seconds"
        ))))
        timer.start(READ_TIMEOUT_MS)

        process.start(argv[0], argv[1:])

    def shutdown(self):
        for process in list(self._running):
            process.kill()
        self._running.clear()
