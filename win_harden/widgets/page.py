"""Page scaffolding: the Qt equivalents of Adw.PreferencesPage and friends.

libadwaita gives you a scrolling page of titled groups of rows for free, which
is most of what the Fedora app's pages are made of. Qt does not, so this module
rebuilds the same four pieces -- page, card, group, banner -- and every page is
then assembled from them exactly as the originals were.

Keeping the vocabulary identical is deliberate: it makes the ported pages read
like their originals, so a change made on one side can be found on the other.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .confirm import escape_markup


class Page(QScrollArea):
    """A scrolling column of groups, with a title at the top."""

    def __init__(self, title, subtitle="", parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self._body = QWidget(self)
        self._layout = QVBoxLayout(self._body)
        self._layout.setContentsMargins(28, 24, 28, 28)
        self._layout.setSpacing(18)

        heading = QLabel(title, self._body)
        heading.setObjectName("pageTitle")
        heading.setWordWrap(True)
        self._layout.addWidget(heading)

        if subtitle:
            sub = QLabel(subtitle, self._body)
            sub.setObjectName("pageSubtitle")
            sub.setWordWrap(True)
            self._layout.addWidget(sub)

        self.setWidget(self._body)

    def add(self, widget):
        self._layout.addWidget(widget)
        return widget

    def add_stretch(self):
        self._layout.addStretch(1)


class Card(QFrame):
    """A bordered container. The Fedora app's Adw.PreferencesGroup, visually."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 14, 16, 14)
        self._layout.setSpacing(10)

    def add(self, widget):
        self._layout.addWidget(widget)
        return widget

    def add_layout(self, layout):
        self._layout.addLayout(layout)
        return layout


class Group(QWidget):
    """A titled section: heading, optional description, then content."""

    def __init__(self, title, subtitle="", parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)

        heading = QLabel(title, self)
        heading.setObjectName("groupTitle")
        heading.setWordWrap(True)
        self._layout.addWidget(heading)

        if subtitle:
            sub = QLabel(subtitle, self)
            sub.setObjectName("groupSubtitle")
            sub.setWordWrap(True)
            self._layout.addWidget(sub)

        self.card = Card(self)
        self._layout.addWidget(self.card)

    def add(self, widget):
        return self.card.add(widget)


class Banner(QFrame):
    """An explanation the page needs to show above everything else.

    The Fedora app used one of these for "the privileged helper isn't
    installed". This port needs several more, because Windows has more ways to
    refuse a change than Linux did -- Tamper Protection, a pending reboot, a
    domain policy -- and each of them means something different for what the
    page below is telling you.
    """

    TONES = ("info", "ok", "warning", "error")

    def __init__(self, title="", body="", tone="info", parent=None):
        super().__init__(parent)
        self.setObjectName("banner")
        self.setProperty("tone", tone if tone in self.TONES else "info")
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        self._title = QLabel(title, self)
        self._title.setObjectName("bannerTitle")
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._body = QLabel(body, self)
        self._body.setWordWrap(True)
        self._body.setTextFormat(Qt.RichText)
        self._body.setOpenExternalLinks(False)
        layout.addWidget(self._body)

        self._actions = QHBoxLayout()
        self._actions.setSpacing(8)
        self._actions.addStretch(1)
        layout.addLayout(self._actions)

        # Tracked explicitly rather than read back from isVisible(): a widget
        # whose window has never been shown reports not-visible regardless of
        # what we set, which makes "is the banner up?" untestable and, worse,
        # unreadable from other code.
        self.showing = bool(title or body)
        self.setVisible(self.showing)

    def show_message(self, title, body, tone="info"):
        self._title.setText(title)
        self._title.setVisible(bool(title))
        self._body.setText(_rich(body))
        self._body.setVisible(bool(body))
        self.setProperty("tone", tone if tone in self.TONES else "info")
        self.style().unpolish(self)
        self.style().polish(self)
        self.showing = True
        self.setVisible(True)

    def add_action(self, label, on_click, accent=False):
        button = QPushButton(label, self)
        if accent:
            button.setProperty("accent", True)
        button.clicked.connect(on_click)
        self._actions.addWidget(button)
        return button

    def hide_message(self):
        self.showing = False
        self.setVisible(False)


def _rich(text):
    paragraphs = [escape_markup(part).replace("\n", "<br>") for part in str(text).split("\n\n")]
    return "<p>" + "</p><p>".join(paragraphs) + "</p>"


class KeyValueRow(QWidget):
    """A label and a value, for status readouts."""

    def __init__(self, label, value="—", tone=None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(12)

        self._label = QLabel(label, self)
        self._label.setWordWrap(True)
        layout.addWidget(self._label, 1)

        self._value = QLabel(str(value), self)
        self._value.setObjectName("riskDot" if tone else "")
        if tone:
            self._value.setProperty("risk", tone)
        self._value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self._value, 0)

    def set_value(self, value, tone=None):
        self._value.setText(str(value))
        if tone:
            self._value.setObjectName("riskDot")
            self._value.setProperty("risk", tone)
            self._value.style().unpolish(self._value)
            self._value.style().polish(self._value)


def unknown_label(value, yes="On", no="Off", unknown="Not reported"):
    """Render a tri-state cleanly.

    None means "we could not read this", which is different from "off" and must
    not be shown as it. Windows returns an absent value for a setting that has
    never been configured, and reporting that as Off would tell the user the
    machine is in a state we never verified.
    """
    if value is None:
        return unknown
    return yes if value else no
