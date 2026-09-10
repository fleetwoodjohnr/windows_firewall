"""Cancellable overlapped named-pipe I/O, with bounded frame sizes."""
import time
from .protocol import MAX_FRAME


def _wait(handle, overlapped, timeout, stop=None):
    import win32event
    import win32file
    handles = [overlapped.hEvent] + ([stop] if stop else [])
    result = win32event.WaitForMultipleObjects(handles, False, max(0, int(timeout * 1000)))
    if result != win32event.WAIT_OBJECT_0:
        win32file.CancelIoEx(handle, overlapped)
        # Drain the cancelled request before releasing its OVERLAPPED/buffer.
        win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
        raise TimeoutError('The local service request timed out or was cancelled.')
    return win32file.GetOverlappedResult(handle, overlapped, False)


def connect(handle, stop=None, timeout=86400):
    import win32event
    import win32pipe
    import pywintypes
    ov = pywintypes.OVERLAPPED()
    ov.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        try:
            win32pipe.ConnectNamedPipe(handle, ov)
        except pywintypes.error as exc:
            if exc.winerror == 535:
                return
            if exc.winerror != 997:
                raise
        _wait(handle, ov, timeout, stop)
    finally:
        ov.hEvent.Close()


def read_frame(handle, timeout=15, stop=None, limit=MAX_FRAME):
    import win32event
    import win32file
    import pywintypes
    data = b''
    deadline = time.monotonic() + timeout
    while b'\n' not in data:
        ov = pywintypes.OVERLAPPED()
        ov.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            buffer = win32file.AllocateReadBuffer(8192)
            win32file.ReadFile(handle, buffer, ov)
            count = _wait(handle, ov, deadline - time.monotonic(), stop)
            if count == 0:
                raise ConnectionError('The local service closed its connection.')
            data += bytes(buffer[:count])
            if len(data) > limit:
                raise ValueError('The local service frame is too large.')
        finally:
            ov.hEvent.Close()
    line, _, remainder = data.partition(b'\n')
    if remainder:
        raise ValueError('Multiple frames in one service exchange are not allowed.')
    return line


def write_frame(handle, data, timeout=15, stop=None):
    import win32event
    import win32file
    import pywintypes
    ov = pywintypes.OVERLAPPED()
    ov.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        win32file.WriteFile(handle, data, ov)
        count = _wait(handle, ov, timeout, stop)
        if count != len(data):
            raise ConnectionError('Incomplete local service write.')
    finally:
        ov.hEvent.Close()
