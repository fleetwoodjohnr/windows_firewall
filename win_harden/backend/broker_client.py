r"""GUI-side client for the elevated broker.

Same shape as the Fedora app's `backend/hardening.py`: a callback-based async
wrapper where nothing blocks the UI thread while an authentication prompt is on
screen. On Linux that prompt was PolicyKit inside a `pkexec` child; here it is
UAC inside `ShellExecuteEx`, and the consequence is the same -- the call sits
open for as long as a person takes to find the prompt and click it.

Reads and writes take different routes, exactly as they did on Fedora:

  * `status` and everything else read-only runs unelevated, in this process,
    through `powershell.py`. Opening a page never prompts.
  * Only apply/revert/set-* go to the broker, and the first of those in a session
    triggers one UAC prompt.

Named pipes block, and Qt's event loop must not, so the pipe lives on a worker
thread and results come back as a queued signal. Callbacks therefore run on the
main thread and may touch widgets directly.

Two details ported verbatim from `hardening.py` because both were learned the
hard way there:

  * A call that never returns must still release the UI. `CALL_TIMEOUT_SECONDS`
    bounds every request.
  * The timeout and the completion path are made mutually exclusive by a single
    `finished` flag, so a late timeout cannot fire after a success and a late
    completion cannot run after a timeout has already been reported.
"""

import os
import queue
import sys
import threading
import uuid
import time

from PySide6.QtCore import QObject, QThread, Signal

from broker.pipe import PIPE_PREFIX, validate_sid
from broker.protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    decode_response,
    encode_request,
)

from .errors import (
    BrokerAuthCancelled,
    BrokerError,
    BrokerTimeout,
    BrokerUnavailable,
    BrokerVersionMismatch,
    error_for_kind,
)

# A UAC prompt sits inside the first privileged call, so this has to allow for a
# person finding a window that may have opened behind others. It exists only so
# a prompt that is never answered can't leave a control greyed out forever.
CALL_TIMEOUT_SECONDS = 180

# After UAC is answered the broker still has to start, create its pipe and
# accept. Polled rather than waited on, because there is no handle to wait for
# until the pipe exists.
CONNECT_TIMEOUT_SECONDS = 60
CONNECT_POLL_SECONDS = 0.25

BROKER_EXE = "win-harden-broker.exe"
_RETIRED_WORKERS = []

# ShellExecute returns a value <= 32 to mean failure. 1223 is
# ERROR_CANCELLED -- the user dismissed the UAC prompt, which is an ordinary
# outcome and must not be reported as a fault.
SE_ERR_CANCELLED = 1223


def broker_path():
    """Locate the broker next to the running executable.

    Resolved from the frozen executable's own directory (or this checkout) and
    never from PATH or the working directory: this is the path we are about to
    ask Windows to run as Administrator, and it must not be something another
    process can influence.
    """
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, BROKER_EXE)


def current_user_sid():  # pragma: no cover - Windows-only
    import win32api  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_QUERY
    )
    sid, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
    token.Close()
    return win32security.ConvertSidToStringSid(sid)


class _Call:
    """One in-flight request. `finished` makes the completion and timeout paths
    mutually exclusive; see the module docstring."""

    def __init__(self, request_id, callback):
        self.id = request_id
        self.callback = callback
        self.finished = False


class _Worker(QObject):  # pragma: no cover - needs Qt + Windows
    """Owns the pipe. Lives on its own thread; every method here runs there."""

    completed = Signal(str, object, object)  # request id, result, error

    def __init__(self):
        super().__init__()
        self._handle = None
        self._buffer = b""
        self._queue = queue.Queue()
        self._stop = threading.Event()

    # -- elevation + connect --------------------------------------------------

    def _launch_broker(self, sid):
        """One UAC prompt. Returns once the prompt has been answered, not once
        the broker is ready -- connecting is a separate, polled step."""
        import win32api  # noqa: PLC0415
        import win32con  # noqa: PLC0415
        import pywintypes  # noqa: PLC0415

        path = broker_path()
        if not os.path.exists(path):
            raise BrokerUnavailable(
                f"the privileged helper is missing from {path}. Reinstall the app."
            )
        try:
            result = win32api.ShellExecute(
                0, "runas", path, f'--client-sid {sid}', os.path.dirname(path),
                win32con.SW_HIDE,
            )
        except pywintypes.error as e:
            if e.winerror == SE_ERR_CANCELLED:
                raise BrokerAuthCancelled(
                    "the Administrator prompt was dismissed, so nothing was changed"
                ) from e
            raise BrokerUnavailable(f"couldn't start the privileged helper: {e}") from e
        if result <= 32:
            raise BrokerUnavailable(
                f"couldn't start the privileged helper (ShellExecute returned {result})"
            )

    def _connect(self, sid, deadline):
        import time  # noqa: PLC0415

        import win32file  # noqa: PLC0415
        import pywintypes  # noqa: PLC0415

        name = PIPE_PREFIX + validate_sid(sid)
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                handle = win32file.CreateFile(
                    name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0x40120000, None,
                )
                from broker.pipe import verify_server_image
                try:
                    verify_server_image(handle, broker_path())
                except Exception:
                    handle.Close()
                    raise
                return handle
            except pywintypes.error:
                time.sleep(CONNECT_POLL_SECONDS)
        raise BrokerUnavailable(
            "the privileged helper started but never accepted a connection. "
            "Check C:\\ProgramData\\win-harden\\broker.log."
        )

    def ensure_connected(self):
        import time  # noqa: PLC0415

        if self._handle is not None:
            return
        sid = current_user_sid()
        # Try an existing broker first: a session that already elevated must not
        # prompt a second time.
        try:
            self._handle = self._connect(sid, time.monotonic() + 0.5)
            self._handshake()
            return
        except BrokerUnavailable:
            self.disconnect()
        self._launch_broker(sid)
        self._handle = self._connect(sid, time.monotonic() + CONNECT_TIMEOUT_SECONDS)
        self._handshake()

    def _handshake(self):
        """Confirm the broker on the other end speaks our protocol before any
        real request. A stale broker left running from a previous version would
        otherwise misread a payload rather than refuse it."""
        result = self._exchange(encode_request(str(uuid.uuid4()), "ping"))
        if result.get("protocol") != PROTOCOL_VERSION:
            raise BrokerVersionMismatch(
                f"the running helper speaks protocol {result.get('protocol')!r}, but this "
                f"app expects {PROTOCOL_VERSION}. Sign out and back in to restart it, or "
                f"reinstall the app."
            )

    # -- framing --------------------------------------------------------------

    def _exchange(self, frame):
        from scanner.ipc import read_frame, write_frame
        from broker.protocol import MAX_FRAME_BYTES, decode_frame
        handle = self._handle
        try:
            write_frame(handle, frame)
            line = read_frame(handle, timeout=CALL_TIMEOUT_SECONDS, limit=MAX_FRAME_BYTES)
        except Exception as exc:
            raise BrokerUnavailable(f'The privileged helper connection failed: {exc}') from exc

        _rid, ok, result, kind, message = decode_response(line)
        if _rid != decode_frame(frame)['id']:
            raise BrokerUnavailable('The helper response did not match this request.')
        if not ok:
            raise error_for_kind(kind, message)
        return result

    # -- request loop ---------------------------------------------------------

    def submit(self, request_id, frame, cancelled):
        self._queue.put((request_id, frame, cancelled))

    def run_loop(self):
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            request_id, frame, cancelled = item
            if cancelled.is_set():
                continue
            try:
                self.ensure_connected()
                if cancelled.is_set() or self._stop.is_set():
                    continue
                result = self._exchange(frame)
            except (BrokerError, ProtocolError) as e:
                self.disconnect()
                self.completed.emit(request_id, None, e)
            except Exception as e:  # noqa: BLE001 - never let the worker thread die
                self.disconnect()
                self.completed.emit(request_id, None, BrokerError(str(e)))
            else:
                self.completed.emit(request_id, result, None)

    def stop(self):
        self._stop.set()
        self.disconnect()

    def disconnect(self):
        handle, self._handle = self._handle, None
        self._buffer = b''
        if handle is not None:
            try:
                import win32file
                win32file.CancelIoEx(handle, None)
                win32file.CloseHandle(handle)
            except Exception:
                pass


class BrokerClient(QObject):
    status_completed = Signal(object, object, object)
    """Public API. Every method is `(..., callback)` where

        callback(result: dict | None, error: WinHardenError | None)

    and runs on the main thread.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._calls = {}
        self._closed = False
        self.status_completed.connect(lambda callback, result, error: callback(result, error))
        self._thread = QThread()
        self._worker = _Worker()
        self._worker.moveToThread(self._thread)
        self._worker.completed.connect(self._on_completed)
        self._thread.started.connect(self._worker.run_loop)
        self._thread.start()

    # -- plumbing -------------------------------------------------------------

    def _send(self, verb, callback, **fields):
        from PySide6.QtCore import QTimer  # noqa: PLC0415

        request_id = str(uuid.uuid4())
        try:
            frame = encode_request(request_id, verb, **fields)
        except ProtocolError as e:
            # The GUI built a request its own validator rejects. Report it
            # rather than send it: this is a bug in the app, not in the machine.
            callback(None, BrokerError(str(e)))
            return

        call = _Call(request_id, callback)
        call.cancelled = threading.Event()
        self._calls[request_id] = call

        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._on_timeout(request_id))
        timer.start(CALL_TIMEOUT_SECONDS * 1000)
        call.timer = timer

        self._worker.submit(request_id, frame, call.cancelled)

    def _finish(self, request_id, result, error):
        call = self._calls.pop(request_id, None)
        if call is None or call.finished:
            return
        call.finished = True
        timer = getattr(call, "timer", None)
        if timer is not None:
            timer.stop()
            timer.deleteLater()
        call.callback(result, error)

    def _on_completed(self, request_id, result, error):
        self._finish(request_id, result, error)

    def _on_timeout(self, request_id):
        call = self._calls.get(request_id)
        if call:
            call.cancelled.set()
        self._finish(request_id, None, BrokerTimeout(
            f"the privileged helper didn't respond within {CALL_TIMEOUT_SECONDS} seconds. "
            "An already-started change may still be running. Refresh system status before retrying."
        ))

    def shutdown(self):
        if self._closed:
            return
        self._closed = True
        for rid, call in list(self._calls.items()):
            call.cancelled.set()
            self._finish(rid, None, BrokerUnavailable('The application is closing.'))
        self._worker.stop()
        self._thread.quit()
        if not self._thread.wait(2000):
            # ShellExecute can still be waiting for UAC. Keep Qt's thread
            # object alive until it returns; destroying it would abort the app.
            _RETIRED_WORKERS.append((self._thread, self._worker))

    # -- verbs ----------------------------------------------------------------

    def status(self, callback):
        def work():
            result, error = None, None
            try:
                from .status import read_status
                result = read_status()
            except Exception as exc:
                error = BrokerUnavailable(str(exc))
            if not self._closed:
                try:
                    self.status_completed.emit(callback, result, error)
                except RuntimeError:
                    pass
        threading.Thread(target=work, name='system-status', daemon=True).start()

    def antivirus_action(self, action, callback):
        self._send('antivirus-action', callback, antivirus_action=action)

    def apply_level(self, family, level, callback):
        self._send("apply", callback, family=family, level=level)

    def revert(self, family, callback):
        self._send("revert", callback, family=family)

    def set_asr_rule(self, rule_id, action, callback):
        self._send("set-asr", callback, asr_rule=rule_id, asr_action=action)

    def set_toggle(self, toggle, enabled, callback):
        self._send("set-toggle", callback, toggle=toggle, enabled=bool(enabled))

    def set_rule_group(self, profile, group, enabled, callback):
        self._send("set-rule-group", callback,
                   profile=profile, group=group, enabled=bool(enabled))

    def set_network_category(self, interface_index, category, callback):
        self._send("set-network-category", callback,
                   interface=int(interface_index), category=category)

    def set_dns_provider(self, provider, interface_index, callback):
        self._send("set-dns-provider", callback, provider=provider, interface=int(interface_index))
