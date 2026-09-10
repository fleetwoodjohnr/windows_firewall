r"""Named-pipe transport between the unelevated GUI and the elevated broker.

Windows has no polkit. There is no way to ask the system "is this user allowed
to do this one thing", get an answer, and go back to being unprivileged. The
choices are to run the whole GUI as Administrator, or to put the privileged code
in a separate process and talk to it. This is the second.

    win-harden.exe (asInvoker, the Qt GUI)
          |  ShellExecuteEx "runas"  ->  one UAC prompt
          v
    win-harden-broker.exe (requireAdministrator, stays alive)
          ^
          |  \\.\pipe\win-harden-<client SID>

Who may connect, and why it is checked twice:

The broker is told its client's SID on the command line and builds the pipe's
DACL to grant that SID, SYSTEM and Administrators -- and nobody else. Everyone
else on the machine, including other standard users, is denied by the OS before
a single byte is read.

Passing the SID in is safe despite coming from the caller, because it can only
ever *narrow* who is served, and because starting a broker at all requires
passing UAC. But a DACL alone would still trust a name, so at accept time the
broker impersonates the client and compares the connecting token's user SID
against the same value. A DACL the OS enforces plus a token check we enforce,
and both must agree.

pywin32 is imported lazily so that importing this module on a non-Windows
machine (to run the tests) does not fail.
"""

import re

PIPE_PREFIX = r"\\.\pipe\win-harden-"

# S-1-<authority>-<sub>-<sub>...
SID_PATTERN = re.compile(r"^S-1-\d{1,10}(-\d{1,10}){1,15}$")

BUFFER_SIZE = 64 * 1024


class PipeError(Exception):
    pass


class AccessRefused(PipeError):
    """A client connected but is not the one this broker was started for."""


def validate_sid(sid):
    """Check a SID string's shape before it reaches a security descriptor."""
    if not isinstance(sid, str) or not SID_PATTERN.match(sid):
        raise PipeError(f"{sid!r} is not a well-formed SID")
    return sid


def pipe_name(sid):
    """One pipe per client SID, so two users on the same machine never share a
    channel even momentarily."""
    return PIPE_PREFIX + validate_sid(sid)


def _win32():
    try:
        # win32api is imported here purely to fail fast alongside the others if
        # pywin32 is only partially present; wait_for_client() imports it again
        # where it is actually used.
        import win32api  # noqa: F401,PLC0415
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415
        import win32security  # noqa: PLC0415
        import pywintypes  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover - Windows-only path
        raise PipeError(
            "pywin32 isn't available, so the privileged broker can't be reached. "
            "Reinstall the app."
        ) from e
    return win32pipe, win32file, win32security, pywintypes


def build_security_attributes(client_sid):
    """A security descriptor granting only the client, SYSTEM and Administrators.

    Explicitly *not* inheriting a default DACL: the default for a named pipe is
    considerably broader than this, and the whole point of the transport is that
    only one account can reach it.
    """
    _pipe, _file, win32security, _types = _win32()  # pragma: no cover - Windows-only
    validate_sid(client_sid)

    client = win32security.ConvertStringSidToSid(client_sid)
    system = win32security.ConvertStringSidToSid("S-1-5-18")
    admins = win32security.ConvertStringSidToSid("S-1-5-32-544")

    dacl = win32security.ACL()
    # GENERIC_READ | GENERIC_WRITE, spelled out rather than FILE_ALL_ACCESS: the
    # client needs to talk on the pipe, not to change its permissions.
    access = 0x80000000 | 0x40000000
    for sid in (client, system, admins):
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, sid)

    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, dacl, 0)

    attributes = _types.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = 0
    return attributes


class PipeServer:  # pragma: no cover - Windows-only
    """Broker side. One connection at a time, by design: the GUI issues one
    privileged change at a time and a queue of concurrent elevated writes is a
    complication with no user-visible benefit."""

    def __init__(self, client_sid):
        self.client_sid = validate_sid(client_sid)
        self.name = pipe_name(client_sid)
        self._handle = None
        self._authenticated = False

    def create(self):
        win32pipe, _file, _security, _types = _win32()
        attributes = build_security_attributes(self.client_sid)
        self._handle = win32pipe.CreateNamedPipe(
            self.name,
            win32pipe.PIPE_ACCESS_DUPLEX | 0x00080000 | 0x40000000,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | 0x8,
            1,                    # one instance: one client, ever
            BUFFER_SIZE, BUFFER_SIZE,
            0,
            attributes,
        )
        return self._handle

    def wait_for_client(self):
        """Accept one connection and verify it is who we were started for."""
        from scanner.ipc import connect
        connect(self._handle, timeout=60)

    def _authenticate(self):
        win32pipe, _file, win32security, pywintypes = _win32()
        # The DACL already refused everyone else. This is the second, independent
        # check: ask the OS who is actually on the other end.
        win32pipe.ImpersonateNamedPipeClient(self._handle)
        try:
            import win32api  # noqa: PLC0415

            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True
            )
            sid, _attr = win32security.GetTokenInformation(token, win32security.TokenUser)
            actual = win32security.ConvertSidToStringSid(sid)
            token.Close()
        finally:
            win32security.RevertToSelf()

        if actual != self.client_sid:
            raise AccessRefused(
                f"a process running as {actual} connected to a broker started for "
                f"{self.client_sid}; refusing to serve it"
            )
        self._authenticated = True

    def read_frame(self):
        from scanner.ipc import read_frame
        try:
            line = read_frame(self._handle, timeout=900 if self._authenticated else 15)
        except (OSError, ConnectionError, TimeoutError):
            return None
        # Impersonation uses the token of the last message read from the pipe.
        if not self._authenticated:
            self._authenticate()
        return line

    def write_frame(self, data):
        from scanner.ipc import write_frame
        write_frame(self._handle, data)

    def close(self):
        if self._handle is None:
            return
        win32pipe, win32file, _security, _types = _win32()
        try:
            win32pipe.DisconnectNamedPipe(self._handle)
        except Exception:  # noqa: BLE001 - closing down; nothing useful to do
            pass
        try:
            win32file.CloseHandle(self._handle)
        except Exception:  # noqa: BLE001
            pass
        self._handle = None


def verify_server_image(handle, expected):
    """Refuse a pipe impersonator before sending a privileged request.

    The installed helper's requireAdministrator manifest and Program Files ACL
    protect the executable whose process image is checked here.
    """
    import ctypes
    from ctypes import wintypes
    import os
    import win32api
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    pid = wintypes.ULONG()
    kernel.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    if not kernel.GetNamedPipeServerProcessId(int(handle), ctypes.byref(pid)):
        raise ctypes.WinError(ctypes.get_last_error())
    process = win32api.OpenProcess(0x1000, False, pid.value)
    try:
        size = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(size.value)
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        if not kernel.QueryFullProcessImageNameW(int(process), 0, path, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if os.path.normcase(os.path.realpath(path.value)) != os.path.normcase(os.path.realpath(expected)):
            raise AccessRefused('The named pipe does not belong to the installed privileged helper.')
    finally:
        process.Close()
