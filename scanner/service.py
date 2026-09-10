"""Windows SCM host. Installed in Program Files; fixed Defender operations only."""
import logging
from pathlib import Path
import threading

from .engine import DefenderEngine
from .jobs import Jobs
from .paths import check_access, program_data, protected_directory
from .protocol import MAX_FRAME, PIPE_NAME, SERVICE_NAME, VERSION, decode, encode, validate
from .ipc import connect, read_frame, write_frame


class ScanServer:
    def __init__(self, jobs):
        self.jobs = jobs
        self.stopped = threading.Event()
        self.handles = set()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)

    def run(self):
        import win32pipe
        import win32file
        import win32security
        import pywintypes
        import win32event
        self.stop_handle = win32event.CreateEvent(None, True, False, None)
        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)', 1)
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        first = True
        while not self.stopped.is_set():
            if not self.slots.acquire(timeout=1):
                continue
            handle = win32pipe.CreateNamedPipe(
                PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX | 0x40000000 | (0x00080000 if first else 0),
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | 0x8,
                9, MAX_FRAME, MAX_FRAME, 5000, sa)
            first = False
            with self.lock:
                self.handles.add(handle)
            try:
                connect(handle, self.stop_handle)
            except Exception:
                with self.lock:
                    self.handles.discard(handle)
                handle.Close()
                self.slots.release()
                if self.stopped.is_set():
                    break
                raise
            threading.Thread(target=self._client, args=(handle,), daemon=True).start()

    def _client(self, handle):
        import win32api
        import win32file
        import win32pipe
        import win32security
        authorization = None
        try:
            request = validate(decode(read_frame(handle, stop=self.stop_handle)))
            win32pipe.ImpersonateNamedPipeClient(handle)
            try:
                token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
                try:
                    sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
                    admin = win32security.CheckTokenMembership(token, win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid))
                finally:
                    token.Close()
                if request['op'] == 'submit' and request['kind'] == 'custom':
                    request['path'] = check_access(request['path'])
                    token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY | win32security.TOKEN_DUPLICATE, True)
                    try:
                        duplicate = win32security.DuplicateToken(token, win32security.SecurityImpersonation)
                        authorization = CallerScope(duplicate, request['path'])
                    finally:
                        token.Close()
            finally:
                win32security.RevertToSelf()
            if request['op'] == 'submit' and request['kind'] in ('remediate', 'protect') and not admin:
                raise PermissionError('This operation requires Administrator approval.')
            if 'owner_sid' in request:
                if not admin or request['kind'] not in ('remediate', 'protect'):
                    raise PermissionError('Only an administrator can submit remediation for another user.')
                sid = request['owner_sid']
            result = self.dispatch(sid, request, authorization)
            authorization = None  # ownership transferred to the durable queue
            response = {'version': VERSION, 'ok': True, 'result': result}
        except Exception as exc:
            response = {'version': VERSION, 'ok': False, 'error': str(exc)}
        try:
            write_frame(handle, encode(response), stop=self.stop_handle)
            # DisconnectNamedPipe discards unread output. Wait for the client to
            # consume the response and close (or acknowledge) before disconnecting.
            try:
                read_frame(handle, timeout=15, stop=self.stop_handle)
            except (OSError, ConnectionError, TimeoutError):
                pass
        except Exception:
            logging.exception('Scanner client disconnected')
        finally:
            if authorization:
                authorization.close()
            with self.lock:
                self.handles.discard(handle)
            try:
                win32pipe.DisconnectNamedPipe(handle)
                handle.Close()
            except Exception:
                pass
            self.slots.release()

    def dispatch(self, sid, request, authorization=None):
        op = request['op']
        if op == 'health':
            return self.jobs.engine.health()
        if op == 'history':
            rows = self.jobs.history(sid)
            # Keep the newest records even when a threat-heavy history would
            # exceed the pipe limit. Never discard details from an individual job.
            import json
            limited = False
            while len(json.dumps({'jobs': rows}, ensure_ascii=True).encode()) > MAX_FRAME - 1024:
                rows.pop()
                limited = True
            return {'jobs': rows, 'limited': limited}
        if op == 'job':
            return self.jobs.get(sid, request['job_id'])
        if op == 'cancel':
            return self.jobs.cancel(sid, request['job_id'])
        return self.jobs.submit(sid, request['kind'], request['request_id'], request.get('path', ''), authorization)

    @staticmethod
    def _cancel_io(handle):
        try:
            import win32file
            win32file.CancelIoEx(handle, None)
        except Exception:
            pass

    def stop(self):
        self.stopped.set()
        if getattr(self, 'stop_handle', None):
            import win32event
            win32event.SetEvent(self.stop_handle)
        with self.lock:
            for handle in list(self.handles):
                self._cancel_io(handle)


class CallerScope:
    def __init__(self, token, path):
        self.token = token
        self.path = path

    def __enter__(self):
        import win32security
        win32security.ImpersonateLoggedOnUser(self.token)
        try:
            check_access(self.path)
        except Exception:
            win32security.RevertToSelf()
            self.close()
            raise
        return self

    def __exit__(self, *_):
        import win32security
        win32security.RevertToSelf()
        self.close()

    def close(self):
        if self.token:
            self.token.Close()
            self.token = None


def main():
    import sys
    import servicemanager
    import win32service
    import win32serviceutil
    if len(sys.argv) > 1:
        return manage(sys.argv[1:])

    class ScannerService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = 'Windows Firewall & Hardening Scanner'
        _svc_description_ = 'Runs Microsoft Defender scans requested by the local download monitor.'

        def __init__(self, args):
            super().__init__(args)
            self.server = None
            self.stop_requested = threading.Event()

        def SvcStop(self):
            self.stop_requested.set()
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.server:
                self.server.stop()

        def SvcDoRun(self):
            root = protected_directory(Path(program_data()) / 'win-harden')
            # Scan records are private to the service; returned only through IPC.
            private = protected_directory(root / 'scanner')
            import win32security
            sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 1)
            win32security.SetNamedSecurityInfo(str(private), win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, sd.GetSecurityDescriptorDacl(), None)
            logging.basicConfig(filename=str(private / 'service.log'), level=logging.INFO)
            jobs = Jobs(private / 'jobs.sqlite3', DefenderEngine())
            self.server = ScanServer(jobs)
            if self.stop_requested.is_set():
                self.server.stop()
            jobs.start()
            try:
                self.server.run()
            finally:
                jobs.stop()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(ScannerService)
    servicemanager.StartServiceCtrlDispatcher()


def manage(args):
    """Installer-only SCM operations; no caller-selected paths or commands."""
    import sys
    import time
    import win32service as ws
    import pywintypes
    if args not in (['--install'], ['--stop'], ['--remove']):
        raise ValueError('Expected --install, --stop, or --remove')
    manager = ws.OpenSCManager(None, None, ws.SC_MANAGER_ALL_ACCESS)
    service = None
    try:
        try:
            service = ws.OpenService(manager, SERVICE_NAME, ws.SERVICE_ALL_ACCESS)
        except pywintypes.error as exc:
            if exc.winerror != 1060:
                raise
        if service and ws.QueryServiceStatus(service)[1] != ws.SERVICE_STOPPED:
            try:
                ws.ControlService(service, ws.SERVICE_CONTROL_STOP)
            except pywintypes.error as exc:
                if exc.winerror != 1062:
                    raise
            deadline = time.monotonic() + 30
            while ws.QueryServiceStatus(service)[1] != ws.SERVICE_STOPPED:
                if time.monotonic() >= deadline:
                    raise RuntimeError('The scan service did not stop. Restart Windows and retry installation.')
                time.sleep(.2)
        if args == ['--remove']:
            if service:
                ws.DeleteService(service)
        elif args == ['--install']:
            path = '"' + str(Path(sys.executable).resolve()) + '"'
            if service:
                ws.ChangeServiceConfig(service, ws.SERVICE_NO_CHANGE, ws.SERVICE_AUTO_START,
                    ws.SERVICE_ERROR_NORMAL, path, None, 0, None, 'LocalSystem', None,
                    'Windows Firewall & Hardening Scanner')
            else:
                service = ws.CreateService(manager, SERVICE_NAME, 'Windows Firewall & Hardening Scanner',
                    ws.SERVICE_ALL_ACCESS, ws.SERVICE_WIN32_OWN_PROCESS, ws.SERVICE_AUTO_START,
                    ws.SERVICE_ERROR_NORMAL, path, None, 0, None, None, None)
            ws.ChangeServiceConfig2(service, ws.SERVICE_CONFIG_FAILURE_ACTIONS,
                {'ResetPeriod': 86400, 'RebootMsg': '', 'Command': '', 'Actions': [(ws.SC_ACTION_RESTART, 30000)] * 3})
            ws.StartService(service, None)
            deadline = time.monotonic() + 30
            while ws.QueryServiceStatus(service)[1] != ws.SERVICE_RUNNING:
                if time.monotonic() >= deadline:
                    raise RuntimeError('The scan service did not start. Check the Windows event log.')
                time.sleep(.2)
    finally:
        if service:
            ws.CloseServiceHandle(service)
        ws.CloseServiceHandle(manager)
    return 0
