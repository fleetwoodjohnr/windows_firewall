"""One bounded connection per request. Verify the server against Windows SCM."""
import ctypes
import uuid

from .protocol import MAX_FRAME, PIPE_NAME, SERVICE_NAME, VERSION, decode, encode, validate
from .ipc import read_frame, write_frame


def request(op, **fields):
    import win32file
    import win32pipe
    import win32service
    payload = validate({'version': VERSION, 'op': op, **fields})
    try:
        win32pipe.WaitNamedPipe(PIPE_NAME, 3000)
        pipe = win32file.CreateFile(PIPE_NAME, 0xC0000000, 0, None, 3, 0x40120000, None)
    except Exception as exc:
        raise RuntimeError('The scan service is unavailable. Repair the installation or start WinHardenScanner in Windows Services.') from exc
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            service = win32service.OpenService(manager, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS)
            status = win32service.QueryServiceStatusEx(service)
            pid = ctypes.c_ulong()
            fn = ctypes.windll.kernel32.GetNamedPipeServerProcessId
            fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            fn.restype = ctypes.c_int
            if not fn(int(pipe), ctypes.byref(pid)) or not pid.value or pid.value != status['ProcessId']:
                raise RuntimeError('The scan pipe does not belong to the installed Windows service.')
        finally:
            if service:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(manager)
        write_frame(pipe, encode(payload))
        response = decode(read_frame(pipe, timeout=70))
        write_frame(pipe, b'\n')
        if response.get('version') != VERSION:
            raise RuntimeError('Scan service version mismatch. Repair the installation.')
        if not response.get('ok'):
            raise RuntimeError(response.get('error', 'Scan operation failed'))
        return response['result']
    finally:
        pipe.Close()


def submit(kind, path=None, request_id=None, owner_sid=None):
    fields = {'kind': kind, 'request_id': request_id or str(uuid.uuid4())}
    if path is not None:
        fields['path'] = path
    if owner_sid:
        fields['owner_sid'] = owner_sid
    return request('submit', **fields)
