"""Qt adapter for the scan service; blocking Windows IPC never runs on the UI."""
import threading
import uuid
from PySide6.QtCore import QObject, Signal
from scanner import client


class ScanClient(QObject):
    finished = Signal(object, object, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.closed = False
        self.finished.connect(self._deliver)

    @staticmethod
    def _deliver(callback, result, error):
        callback(result, error)

    def call(self, op, callback, **fields):
        def work():
            result, error = None, None
            try:
                result = client.request(op, **fields)
            except Exception as exc:
                error = exc
            if not self.closed:
                try:
                    self.finished.emit(callback, result, error)
                except RuntimeError:
                    pass
        threading.Thread(target=work, name='scan-client', daemon=True).start()

    def submit(self, kind, callback, path=None):
        fields = {'kind': kind, 'request_id': str(uuid.uuid4())}
        if path is not None:
            fields['path'] = path
        self.call('submit', callback, **fields)

    def shutdown(self):
        self.closed = True
