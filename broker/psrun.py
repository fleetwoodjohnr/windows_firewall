"""Synchronous PowerShell runner for the elevated broker.

The GUI has its own threaded async runner (win_harden/backend/powershell.py)
because it must never block the UI. The broker is a single-threaded request
loop that is already inside a call the GUI is waiting on, so here blocking is
correct and simpler.

Both build their argv through `psinvoke.build_argv`, which is the only place
allowed to decide what may be executed.
"""

import json
import subprocess

from .psinvoke import InvocationError, build_argv
from .winprocess import creation_flags

# A level can touch a dozen settings, and Set-MpPreference in particular is slow
# on a machine that is mid-signature-update. Generous, but bounded: a script that
# hangs forever would leave the GUI's control greyed out with no way back.
DEFAULT_TIMEOUT = 300


class PowerShellFailed(Exception):
    def __init__(self, message, status=None, stderr=""):
        super().__init__(message)
        self.status = status
        self.stderr = stderr


def run_script(script, params=None, timeout=DEFAULT_TIMEOUT, script_root=None):
    """Run one shipped script and return its parsed JSON output.

    Never a shell, never a -Command string: see psinvoke's module docstring.
    """
    try:
        argv = build_argv(script, params, script_root=script_root)
    except InvocationError as e:
        raise PowerShellFailed(f"refused to run {script}: {e}") from e

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True, encoding='utf-8-sig', errors='replace',
            timeout=timeout,
            check=False,
            # No shell, and an explicit empty stdin so a script that unexpectedly
            # reads from it fails fast rather than hanging the broker.
            stdin=subprocess.DEVNULL,
            creationflags=creation_flags(),
        )
    except FileNotFoundError as e:
        raise PowerShellFailed("powershell.exe couldn't be found", status=None) from e
    except subprocess.TimeoutExpired as e:
        raise PowerShellFailed(
            f"{script} didn't finish within {timeout} seconds and was stopped",
            status=None,
        ) from e

    if completed.returncode != 0:
        raise PowerShellFailed(
            (completed.stderr or completed.stdout or "").strip()
            or f"{script} exited with status {completed.returncode}",
            status=completed.returncode,
            stderr=completed.stderr or "",
        )

    output = (completed.stdout or "").strip()
    if not output:
        return {}
    try:
        parsed = json.loads(output)
    except ValueError as e:
        raise PowerShellFailed(
            f"{script} produced output that isn't JSON: {e}", status=0, stderr=output[:500]
        ) from e
    # ConvertTo-Json emits a bare array for a collection; normalise so callers
    # always get a dict.
    return parsed if isinstance(parsed, dict) else {"items": parsed}


def make_runner(script_root=None):
    """A `runner(script, params) -> dict` closure, which is what Context and
    WindowsProbes expect."""

    def runner(script, params=None):
        return run_script(script, params, script_root=script_root)

    return runner
