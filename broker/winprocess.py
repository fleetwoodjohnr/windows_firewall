"""One policy for Windows child processes that must never create a console."""

import os


# WinBase.h. Kept here rather than as repeated magic numbers so every runtime
# launcher can be audited and tested against the same rule.
CREATE_NO_WINDOW = 0x08000000


def creation_flags(platform=None):
    """Flags for subprocess.Popen/run without harming portable tests."""
    platform = os.name if platform is None else platform
    return CREATE_NO_WINDOW if platform == "nt" else 0
