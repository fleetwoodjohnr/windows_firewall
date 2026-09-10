"""One switchable thing in a list: a row with a risk dot, a title, a one-line
summary, an on/off switch, and an expandable explanation.

Ported from the Fedora app's `widgets/service_row.py`, and the load-bearing part
is the same:

    The switch never flips optimistically. The visible position only changes
    once the write actually succeeds -- or is confirmed to have failed.

Qt makes this slightly more work than GTK did. `Gtk.Switch` has a `state-set`
signal designed for exactly this; the shared `StateBackedSwitch` controller
provides the same contract for Qt, including one-shot completion and a disabled
pending state.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
)

from .state_switch import StateBackedSwitch, SwitchControl

RISK_CLASS = {"low": "ok", "medium": "warn", "high": "bad"}


class ToggleRow(QFrame):
    """`on_toggle(key, requested_state, done)` where `done(ok, error)`."""

    expanded_first_time = Signal(str)

    def __init__(self, key, info, enabled, on_toggle, on_error, parent=None):
        super().__init__(parent)
        self.key = key
        self.info = info
        self._on_toggle = on_toggle
        self._on_error = on_error
        self._expanded_once = False

        self.setObjectName("toggleRow")
        self.setProperty("risk", info.risk)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(10)

        dot = QLabel("●", self)
        dot.setObjectName("riskDot")
        dot.setProperty("risk", RISK_CLASS.get(info.risk, "warn"))
        dot.setToolTip(f"Risk if enabled on an untrusted network: {info.risk}")
        header.addWidget(dot, 0, Qt.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(2)
        title = QLabel(info.label, self)
        title.setObjectName("rowTitle")
        title.setWordWrap(True)
        self._summary = QLabel(info.summary, self)
        self._summary.setObjectName("rowSubtitle")
        self._summary.setWordWrap(True)
        text.addWidget(title)
        text.addWidget(self._summary)
        header.addLayout(text, 1)

        self._expander = QToolButton(self)
        self._expander.setText("▾")
        self._expander.setCheckable(True)
        self._expander.setObjectName("expander")
        self._expander.setToolTip("Show the full explanation")
        self._expander.toggled.connect(self._on_expanded)
        header.addWidget(self._expander, 0, Qt.AlignTop)

        self._switch = SwitchControl(self, accessible_name=info.label)
        self._switch.setAccessibleDescription(info.summary)
        self._state_switch = StateBackedSwitch(
            self._switch, self._request_toggle, parent=self
        )
        self._state_switch.set_applied(bool(enabled))
        header.addWidget(self._switch, 0, Qt.AlignTop)

        outer.addLayout(header)

        self._detail = QLabel(self._detail_text(), self)
        self._detail.setObjectName("rowDetail")
        self._detail.setWordWrap(True)
        self._detail.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self._detail.setVisible(False)
        outer.addWidget(self._detail)

    # -- content --------------------------------------------------------------

    def _detail_text(self):
        return f"{self.info.recommendation}\n\nCategory: {self.info.category}"

    def set_detail_text(self, summary, recommendation):
        self._summary.setText(summary)
        self.info = self.info.__class__(**{**self.info.__dict__, "recommendation": recommendation})
        self._detail.setText(self._detail_text())

    def _on_expanded(self, expanded):
        self._detail.setVisible(expanded)
        self._expander.setText("▴" if expanded else "▾")
        if expanded and not self._expanded_once:
            self._expanded_once = True
            self.expanded_first_time.emit(self.key)

    def matches(self, query):
        if not query:
            return True
        query = query.lower()
        return (
            query in self.key.lower()
            or query in self.info.label.lower()
            or query in self.info.summary.lower()
        )

    # -- state ----------------------------------------------------------------

    def set_enabled_state(self, enabled):
        """Sync to backend state without triggering a write."""
        self._state_switch.set_applied(bool(enabled))

    def _request_toggle(self, requested, state_done):
        def done(ok, error=None):
            state_done(ok)
            if error is not None:
                self._on_error(self.key, requested, error)

        self._on_toggle(self.key, requested, done)
