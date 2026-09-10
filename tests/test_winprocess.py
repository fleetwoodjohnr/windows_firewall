"""No runtime child process may create a console window."""

from broker.winprocess import CREATE_NO_WINDOW, creation_flags


def test_subprocess_creation_flags_are_platform_scoped():
    assert creation_flags("nt") == CREATE_NO_WINDOW
    assert creation_flags("posix") == 0
