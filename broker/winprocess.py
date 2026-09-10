"""One policy for Windows child processes that must never create a console."""

import os


# WinBase.h. Kept here rather than as repeated magic numbers so every runtime
# launcher can be audited and tested against the same rule.
CREATE_NO_WINDOW = 0x08000000


def creation_flags(platform=None):
    """Flags for subprocess.Popen/run without harming portable tests."""
    platform = os.name if platform is None else platform
    return CREATE_NO_WINDOW if platform == "nt" else 0


def configure_qprocess_no_window(process, platform=None):
    """Apply CREATE_NO_WINDOW to a QProcess before it starts.

    Qt exposes this modifier only in Windows builds.  If a future pinned Windows
    Qt loses the API, fail the status read rather than regress to flashing a
    console window every time a page refreshes.
    """
    platform = os.name if platform is None else platform
    if platform != "nt":
        return
    setter = getattr(process, "setCreateProcessArgumentsModifier", None)
    if setter is None:
        raise RuntimeError("This Qt build cannot start PowerShell without a console window.")

    def add_no_window(arguments):
        arguments.flags |= CREATE_NO_WINDOW

    # Keep the Python callable alive for the full QProcess lifetime.
    process._win_harden_create_process_modifier = add_no_window
    setter(add_no_window)
