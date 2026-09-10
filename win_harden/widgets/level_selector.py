"""A hardening level picker: one control with four notches, plus the plain-English
consequences of whichever notch you are looking at.

Ported from the Fedora app's `widgets/level_selector.py`, and the reason the
widget exists is unchanged, so it is worth restating:

    The description below the control is the point. Picking "Strict" out of a
    dropdown tells you nothing; the point is to read what it turns on and what
    it will break *before* committing. So clicking a notch applies nothing -- it
    swaps the description to that level and asks for confirmation, and the
    control only moves once the change has actually landed.

That last sentence is the non-optimistic rule every control in this app follows:
the visible position always reflects the system, never the request. On Windows
it matters more than it did on Fedora, not less, because more changes here can
be silently refused -- Tamper Protection, a domain policy, a licence tier. A
control that moved on click would report protection the machine does not have.

`Adw.ToggleGroup` becomes a `QButtonGroup` of checkable buttons; the rest of the
logic is the same, including the `_syncing` guard around every programmatic move.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QButtonGroup, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .confirm import confirm, escape_markup


class LevelSelector(QWidget):
    def __init__(self, levels, on_apply, window, confirm_heading, parent=None):
        super().__init__(parent)
        self._levels = list(levels)
        self._on_apply = on_apply
        self._window = window
        self._confirm_heading = confirm_heading
        self._active_index = 0
        self._syncing = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self._buttons = []
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        row = QWidget(self)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)
        for index, level in enumerate(self._levels):
            button = QPushButton(level.label, row)
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            # Position drives the rounded-corner styling in style.qss; naming it
            # here keeps that knowledge out of the stylesheet's selectors.
            button.setProperty(
                "segment",
                "first" if index == 0 else "last" if index == len(self._levels) - 1 else "middle",
            )
            self._group.addButton(button, index)
            self._buttons.append(button)
            row_layout.addWidget(button, 1)
        self._buttons[0].setChecked(True)
        self._row = row
        layout.addWidget(row)

        self._description = QLabel(self)
        self._description.setWordWrap(True)
        self._description.setTextFormat(Qt.RichText)
        self._description.setObjectName("levelDescription")
        self._description.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        layout.addWidget(self._description)

        self._group.idClicked.connect(self._requested)

        self._show_description(0)
        self._sync_level_class()

    # -- control position -----------------------------------------------------

    def _set_index(self, index):
        """Move the control without triggering an apply."""
        self._syncing = True
        self._buttons[index].setChecked(True)
        self._syncing = False

    # -- selection handling ---------------------------------------------------

    def _requested(self, index):
        if self._syncing:
            return
        if index < 0 or index >= len(self._levels):
            return
        if index == self._active_index:
            return
        level = self._levels[index]

        # Show what was just clicked straight away, so the confirmation dialog
        # isn't the first place they read it -- then put the control back where
        # the system actually is until the change succeeds.
        self._show_description(index)
        self._set_index(self._active_index)

        def apply():
            self._set_enabled_during_apply(False)

            def done(ok, error=None):
                self._set_enabled_during_apply(True)
                if ok:
                    self._active_index = index
                    self._set_index(index)
                    self._show_description(index)
                    self._sync_level_class()
                else:
                    # Failed, refused or blocked: the control stays where the
                    # system is, and the description goes back with it.
                    self._show_description(self._active_index)

            self._on_apply(level, done)

        def cancelled():
            self._show_description(self._active_index)

        confirm(
            self._window,
            f"{self._confirm_heading}: {level.label}?",
            f"{level.detail}\n\nWhat this might break:\n{level.breaks}",
            f"Switch to {level.label}",
            apply,
            cancelled,
            # Match the Fedora control: every change is confirmed, but only the
            # compatibility-breaking Strict level uses destructive appearance.
            destructive=level.id == "strict",
        )

    def _set_enabled_during_apply(self, enabled):
        self._row.setEnabled(enabled)

    # -- appearance -----------------------------------------------------------

    def _sync_level_class(self):
        """Tag the control with the applied level so style.qss can colour it
        red -> amber -> green.

        Driven by `_active_index`, never by what is being previewed: the colour
        is a readout of applied state, and it would be actively misleading for it
        to go green before the change had landed.
        """
        level_id = self._levels[self._active_index].id
        for index, button in enumerate(self._buttons):
            button.setProperty("level", level_id)
            button.setProperty("applied", index == self._active_index)
            # Qt does not re-evaluate property selectors on its own.
            button.style().unpolish(button)
            button.style().polish(button)

    def _show_description(self, index):
        level = self._levels[index]
        current = " (current)" if index == self._active_index else ""
        parts = [
            f"<b>{escape_markup(level.label)}{current}</b> — {escape_markup(level.summary)}",
            escape_markup(level.detail).replace("\n\n", "<br><br>"),
            f"<b>What this might break:</b> {escape_markup(level.breaks)}",
        ]
        self._description.setText("<p>" + "</p><p>".join(parts) + "</p>")

    # -- external state sync --------------------------------------------------

    def set_active_level(self, level_id):
        """Point the control at what the system actually reports, without
        applying anything. Used on load and after every status refresh."""
        for index, level in enumerate(self._levels):
            if level.id == level_id:
                self._active_index = index
                self._set_index(index)
                self._show_description(index)
                self._sync_level_class()
                return
        self._active_index = 0
        self._set_index(0)
        self._show_description(0)
        self._sync_level_class()

    def get_active_level(self):
        return self._levels[self._active_index]
