"""Switch visuals and the confirmed-state interaction contract."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from win_harden.widgets.state_switch import StateBackedSwitch, SwitchControl, SwitchRow


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def make_switch(qapp, applied=False, request=None):
    control = SwitchControl(accessible_name="Test setting")
    state = StateBackedSwitch(control, request or (lambda _wanted, _done: None))
    state.set_applied(applied)
    return control, state


def test_unknown_state_is_disabled_until_windows_reports_it(qapp):
    control = SwitchControl()
    state = StateBackedSwitch(control, lambda *_args: None)
    assert not control.isEnabled()
    state.set_applied(False)
    assert control.isEnabled()


def test_programmatic_sync_never_requests_a_change(qapp):
    calls = []
    control, state = make_switch(qapp, request=lambda *args: calls.append(args))
    state.set_applied(True)
    state.set_applied(False)
    assert calls == []


def test_request_stays_at_reality_until_delayed_success(qapp):
    pending = []
    control, state = make_switch(qapp, request=lambda wanted, done: pending.append((wanted, done)))
    control.click()
    assert pending[0][0] is True
    assert control.isChecked() is False
    assert not control.isEnabled()
    assert state.pending
    pending[0][1](True)
    assert control.isChecked() is True
    assert control.isEnabled()
    assert not state.pending


def test_failure_and_duplicate_completion_leave_original_state(qapp):
    callbacks = []
    control, state = make_switch(qapp, applied=True,
        request=lambda _wanted, done: callbacks.append(done))
    control.click()
    callbacks[0](False)
    callbacks[0](True)
    assert control.isChecked() is True
    assert state.applied is True


def test_unavailable_switch_does_not_accept_requests(qapp):
    calls = []
    control, state = make_switch(qapp, request=lambda *args: calls.append(args))
    state.set_available(False)
    control.click()
    assert not control.isEnabled()
    assert calls == []


def test_switch_rendering_uses_state_colour_and_thumb_position(qapp):
    qapp.setProperty("winHardenDarkTheme", False)
    control = SwitchControl()
    control.show()
    qapp.processEvents()

    control.setChecked(False)
    off = control.grab().toImage()
    off_track = off.pixelColor(22, 12)
    off_left_thumb = off.pixelColor(11, 12)

    control.setChecked(True)
    on = control.grab().toImage()
    on_track = on.pixelColor(22, 12)
    on_right_thumb = on.pixelColor(33, 12)

    assert off_track.red() > off_track.green()
    assert on_track.green() > on_track.red()
    assert off_left_thumb.lightness() > off_track.lightness()
    assert on_right_thumb.lightness() > on_track.lightness()
    assert control.sizeHint().width() >= 40 and control.sizeHint().height() >= 20
    assert control.focusPolicy() == Qt.StrongFocus


def test_switch_semantics_remain_clear_in_dark_theme(qapp):
    qapp.setProperty("winHardenDarkTheme", True)
    control = SwitchControl()
    control.show()
    qapp.processEvents()
    control.setChecked(False)
    off = control.grab().toImage().pixelColor(22, 12)
    control.setChecked(True)
    on = control.grab().toImage().pixelColor(22, 12)
    assert off.red() > off.green()
    assert on.green() > on.red()
    qapp.setProperty("winHardenDarkTheme", False)


def test_labelled_row_exposes_checked_state_and_explanation(qapp):
    row = SwitchRow("Automatic checks", "Nothing downloads until you ask.", checked=True)
    assert row.isChecked()
    assert row.control.accessibleName() == "Automatic checks"
    assert "Nothing downloads" in row.control.accessibleDescription()
