"""Coalesce a burst of refresh requests into one.

Ported from the Fedora app's `widgets/debounce.py`. The need is the same and if
anything sharper: a single `Set-NetFirewallRule` can emit several change
notifications, and each Windows read is a fresh `powershell.exe` costing a
couple of hundred milliseconds. Refreshing per notification would spawn a
handful of processes to compute the same answer.
"""

from PySide6.QtCore import QObject, QTimer


class Debouncer(QObject):
    """Call `func` once, `delay_ms` after the last request."""

    def __init__(self, func, delay_ms=250, parent=None):
        super().__init__(parent)
        self._func = func
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(delay_ms)
        self._timer.timeout.connect(self._fire)

    def request(self):
        self._timer.start()

    def cancel(self):
        self._timer.stop()

    def flush(self):
        """Run now if something is pending -- used before a read whose answer
        the caller needs immediately."""
        if self._timer.isActive():
            self._timer.stop()
            self._fire()

    def _fire(self):
        self._func()
