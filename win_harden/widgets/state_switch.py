"""Windows switch controls whose position reports confirmed state.

Qt exposes check boxes but no native desktop toggle switch.  The Fedora app
uses one visual language everywhere -- red and left means Off, green and right
means On -- so this module supplies that language once for every Windows page.

``SwitchControl`` is only presentation and ordinary checked-state signalling.
``StateBackedSwitch`` adds the safety contract used for machine settings: a
request snaps back to the last state read from Windows and only moves after the
operation reports success.
"""

from PySide6.QtCore import QObject, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QApplication, QCheckBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget


_LIGHT_OFF = QColor("#c42b1c")
_LIGHT_ON = QColor("#0f7b0f")
_DARK_OFF = QColor("#ff99a4")
_DARK_ON = QColor("#6ccb5f")


class SwitchControl(QCheckBox):
    """An accessible pill switch with the normal QCheckBox API.

    Position, checked state and the accessible check-box role all communicate the
    state without relying on red/green colour.  The widget deliberately carries
    no text; its containing row supplies the visible and accessible label.
    """

    def __init__(self, parent=None, *, accessible_name=""):
        super().__init__(parent)
        self.setObjectName("stateSwitch")
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setFixedSize(self.sizeHint())
        if accessible_name:
            self.setAccessibleName(accessible_name)
        self.toggled.connect(lambda _checked: self.update())

    def sizeHint(self):
        return QSize(44, 24)

    def minimumSizeHint(self):
        return self.sizeHint()

    def hitButton(self, position):
        return self.rect().contains(position)

    @staticmethod
    def _dark_theme():
        app = QApplication.instance()
        if app is not None:
            selected = app.property("winHardenDarkTheme")
            if selected is not None:
                return bool(selected)
            colour = app.palette().window().color()
            return colour.lightness() < 128
        return False

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        dark = self._dark_theme()
        track = (_DARK_ON if self.isChecked() else _DARK_OFF) if dark else (
            _LIGHT_ON if self.isChecked() else _LIGHT_OFF
        )
        if self.underMouse() and self.isEnabled():
            track = track.lighter(112 if dark else 106)

        painter.save()
        if not self.isEnabled():
            painter.setOpacity(0.42)

        track_rect = QRectF(2.0, 3.0, 40.0, 18.0)
        painter.setPen(QPen(track.darker(125), 1.0))
        painter.setBrush(track)
        painter.drawRoundedRect(track_rect, 9.0, 9.0)

        thumb_x = 26.0 if self.isChecked() else 4.0
        thumb = QColor("#151515") if dark else QColor("#ffffff")
        painter.setPen(QPen(QColor(0, 0, 0, 90) if not dark else QColor(255, 255, 255, 100), 0.8))
        painter.setBrush(thumb)
        painter.drawEllipse(QRectF(thumb_x, 5.0, 14.0, 14.0))
        painter.restore()

        if self.hasFocus():
            focus = self.palette().highlight().color()
            painter.setPen(QPen(focus, 2.0))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(QRectF(1.0, 1.0, 42.0, 22.0), 11.0, 11.0)


class StateBackedSwitch(QObject):
    """Keep a switch pointed at confirmed machine state.

    ``on_request(wanted, done)`` receives genuine user requests only.  It must
    call ``done(True)`` after a successful operation or ``done(False)`` after a
    refusal/cancellation/failure.  A completion is accepted once; late duplicate
    callbacks cannot issue a second visible transition.
    """

    def __init__(self, control, on_request, parent=None):
        super().__init__(parent or control)
        self.control = control
        self._on_request = on_request
        self._applied = None
        self._available = True
        self._pending = False
        self._request_serial = 0
        control.setEnabled(False)
        control.clicked.connect(self._on_clicked)

    @property
    def applied(self):
        return self._applied

    @property
    def pending(self):
        return self._pending

    def set_available(self, available):
        self._available = bool(available)
        self._sync_enabled()

    def set_applied(self, value):
        """Point at a value read from Windows without generating a request."""
        self._applied = bool(value)
        self.control.setChecked(self._applied)
        self._sync_enabled()

    def _sync_enabled(self):
        self.control.setEnabled(
            self._available and self._applied is not None and not self._pending
        )

    def _on_clicked(self, wanted):
        wanted = bool(wanted)
        if self._applied is None or self._pending or not self._available:
            self.control.setChecked(bool(self._applied))
            return
        if wanted == self._applied:
            return

        # QCheckBox has already moved. Put it back before yielding to a dialog or
        # backend so its position never claims an unconfirmed Windows state.
        self.control.setChecked(self._applied)
        self._pending = True
        self._request_serial += 1
        serial = self._request_serial
        self._sync_enabled()
        completed = False

        def done(ok):
            nonlocal completed
            if completed or serial != self._request_serial:
                return
            completed = True
            if ok:
                self._applied = wanted
            self.control.setChecked(self._applied)
            self._pending = False
            self._sync_enabled()

        try:
            self._on_request(wanted, done)
        except Exception:
            done(False)
            raise


class SwitchRow(QWidget):
    """A simple labelled preference row containing a ``SwitchControl``."""

    toggled = Signal(bool)
    clicked = Signal(bool)

    def __init__(self, title, subtitle="", checked=False, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 7, 0, 7)
        layout.setSpacing(14)

        text = QVBoxLayout()
        text.setSpacing(2)
        heading = QLabel(title, self)
        heading.setObjectName("rowTitle")
        heading.setWordWrap(True)
        text.addWidget(heading)
        if subtitle:
            detail = QLabel(subtitle, self)
            detail.setObjectName("rowSubtitle")
            detail.setWordWrap(True)
            text.addWidget(detail)
        layout.addLayout(text, 1)

        self.control = SwitchControl(self, accessible_name=title)
        self.control.setAccessibleDescription(subtitle)
        self.control.setChecked(bool(checked))
        self.control.toggled.connect(self.toggled.emit)
        self.control.clicked.connect(self.clicked.emit)
        layout.addWidget(self.control, 0, Qt.AlignVCenter)

    def isChecked(self):
        return self.control.isChecked()

    def setChecked(self, checked):
        self.control.setChecked(bool(checked))
