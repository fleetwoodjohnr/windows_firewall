"""No runtime child process may create a console window."""

import os

import pytest

from broker.winprocess import (
    CREATE_NO_WINDOW,
    configure_qprocess_no_window,
    creation_flags,
)


class FakeProcess:
    def __init__(self):
        self.modifier = None

    def setCreateProcessArgumentsModifier(self, modifier):
        self.modifier = modifier


class Arguments:
    flags = 0x10


def test_subprocess_creation_flags_are_platform_scoped():
    assert creation_flags("nt") == CREATE_NO_WINDOW
    assert creation_flags("posix") == 0


def test_qprocess_modifier_adds_no_window_without_dropping_qt_flags():
    process = FakeProcess()
    configure_qprocess_no_window(process, platform="nt")
    arguments = Arguments()
    process.modifier(arguments)
    assert arguments.flags == 0x10 | CREATE_NO_WINDOW
    assert process._win_harden_create_process_modifier is process.modifier


def test_qprocess_modifier_is_a_noop_off_windows():
    process = object()
    configure_qprocess_no_window(process, platform="posix")


@pytest.mark.skipif(os.name != "nt", reason="Windows Qt exposes the CreateProcess hook")
def test_pinned_windows_qt_exposes_the_no_window_modifier():
    from PySide6.QtCore import QProcess

    process = QProcess()
    configure_qprocess_no_window(process)
    assert process.createProcessArgumentsModifier() is not None
