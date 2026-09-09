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
        # id(process) -> (process, finish). Keyed by id rather than held as a
        # list so shutdown can complete each pending call.
        self._running = {}

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

        # `finished` and the timeout are made mutually exclusive by this flag,
        # the same guard the broker client uses: a late timeout must not fire
        # after a completion, and vice versa.
        state = {"done": False, "timer": None}

        def finish(result, error):
            if state["done"]:
                return
            state["done"] = True
            timer = state["timer"]
            if timer is not None:
                timer.stop()
            self._running.pop(id(process), None)
            # Disconnect before deleting. Qt can still emit finished() or
            # errorOccurred() for a process that is on its way out, and a handler
            # that runs after deleteLater() touches a C++ object Python still has
            # a wrapper for -- which raises inside a signal handler, where there
            # is nobody to catch it.
            try:
                process.finished.disconnect()
                process.errorOccurred.disconnect()
            except (RuntimeError, TypeError):
                pass
            process.deleteLater()
            callback(result, error)

        def on_finished(exit_code, _exit_status):
            # Qt can deliver finished() and errorOccurred() for the same run, and
            # `finish` has already called deleteLater() by the time the second
            # arrives. Reading anything off the QProcess after that raises on the
            # deleted C++ object, so the guard has to come before the first touch
            # rather than inside `finish`.
            if state["done"]:
                return
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
            if state["done"]:
                return
            # Read the message while the object is still alive.
            message = process.errorString()
            finish(None, PowerShellNotFound(f"couldn't run powershell.exe: {message}"))

        process.finished.connect(on_finished)
        process.errorOccurred.connect(on_error)
        # Keyed by id so shutdown can finish each pending call rather than
        # killing the process and leaving its caller waiting forever.
        self._running[id(process)] = (process, finish)

        from PySide6.QtCore import QTimer  # noqa: PLC0415

        def on_timeout():
            if state["done"]:
                return
            process.kill()
            finish(None, PowerShellError(
                f"{script} didn't finish within {READ_TIMEOUT_MS // 1000} seconds"))

        # Parented to the runner, not to the process: a timer owned by the
        # QProcess would be destroyed by deleteLater() mid-callback.
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(on_timeout)
        timer.start(READ_TIMEOUT_MS)
        state["timer"] = timer

        process.start(argv[0], argv[1:])

    def shutdown(self):
        """Kill anything in flight AND complete its callback.

        Killing without finishing was a real bug: the call stayed live with its
        signals connected, and Qt then emitted errorOccurred on a process that
        had already been destroyed. Every pending call gets an answer, which is
        the same rule the broker client follows -- a caller left waiting on a
        reply that never comes is a control greyed out forever.
        """
        for process, finish in list(self._running.values()):
            finish(None, PowerShellError("the application is closing"))
            process.kill()
            # Bounded wait so the child is reaped before its wrapper goes away.
            # Without it Qt warns "Destroyed while process is still running" on
            # every exit, which is noise that trains you to ignore the log.
            process.waitForFinished(200)
        self._running.clear()
