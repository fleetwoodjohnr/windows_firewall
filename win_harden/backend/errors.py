"""Backend error hierarchy, ported from the Fedora app's backend/errors.py.

The shape is unchanged: a base class, a small set of subclasses that the UI
reacts to differently, and translators that turn a raw failure into one of them.
The classifications are what changed, because the failure modes did.

The distinction that matters most here is the one that did not exist on Linux:
a change can be refused by the operating system rather than fail. Tamper
Protection rejects a Defender write, a licence tier withholds a feature, a
domain policy overrides a local setting. Presenting any of those as "it didn't
work" would be a lie -- the app did exactly what it was told and Windows said
no. `ChangeBlocked` exists so the page can say which happened.
"""

from broker.protocol import (
    ERR_BLOCKED,
    ERR_FAILED,
    ERR_GUARD,
    ERR_PROTOCOL,
    ERR_TIMEOUT,
    ERR_VALIDATION,
)


class WinHardenError(Exception):
    """Base class for all backend errors."""


class PowerShellError(WinHardenError):
    """A PowerShell invocation failed."""


class PowerShellNotFound(PowerShellError):
    """powershell.exe could not be run at all."""


class AccessDenied(WinHardenError):
    """The operation needs privileges this process doesn't have."""


class ChangeBlocked(WinHardenError):
    """Windows refused the change: Tamper Protection, group policy, or a
    licence tier. The app did the right thing and was told no -- distinct from
    a failure, and it must be reported as such."""


class GuardRefused(WinHardenError):
    """A guard rail refused, because applying this could lock you out of the
    machine. Not an error: the app protecting you from a setting. The message
    is user-facing prose explaining what to do instead."""


# -- broker errors ------------------------------------------------------------

class BrokerError(WinHardenError):
    """The privileged broker failed for a reason other than the ones below."""


class BrokerUnavailable(BrokerError):
    """The broker isn't running and couldn't be started."""


class BrokerAuthCancelled(BrokerError):
    """The user dismissed the UAC prompt. Expected, not a fault."""


class BrokerVersionMismatch(BrokerError):
    """The broker speaks a different protocol than this app expects."""


class BrokerTimeout(BrokerError):
    """The broker didn't answer in time."""


# Kind -> exception, for responses that already carry a classification. The
# broker did the classifying with far more context than the GUI has, so this is
# a lookup rather than a second guess.
_KIND_ERRORS = {
    ERR_PROTOCOL: BrokerVersionMismatch,
    ERR_VALIDATION: BrokerError,
    ERR_GUARD: GuardRefused,
    ERR_BLOCKED: ChangeBlocked,
    ERR_FAILED: BrokerError,
    ERR_TIMEOUT: BrokerTimeout,
}


def error_for_kind(kind, message):
    return _KIND_ERRORS.get(kind, BrokerError)(message)


# -- PowerShell classification ------------------------------------------------
#
# Unlike the broker path there is no structured status to read, so this is
# substring matching on what PowerShell wrote to stderr. Kept narrow and
# documented as best-effort, in the same spirit as the Fedora app's
# translate_dbus_error.

_ACCESS_MARKERS = (
    "access is denied",
    "requires elevation",
    "unauthorizedaccessexception",
    "requested registry access is not allowed",
    "administrator privilege",
)

_BLOCKED_MARKERS = (
    "tamper",
    "0x800106ba",              # Defender service failed to start / is managed
    "blocked by your administrator",
    "managed by your organization",
    "this setting is managed",
    "not supported on this edition",
    "requires a license",
)


def translate_powershell_error(status, stderr):
    """Classify a failed PowerShell run into the hierarchy above."""
    message = (stderr or "").strip()
    lowered = message.lower()

    if any(marker in lowered for marker in _BLOCKED_MARKERS):
        return ChangeBlocked(message or "Windows refused this change")
    if any(marker in lowered for marker in _ACCESS_MARKERS):
        return AccessDenied(message or "this change needs Administrator rights")
    if status is None:
        return PowerShellNotFound(
            message or "powershell.exe couldn't be started"
        )
    return PowerShellError(message or f"PowerShell exited with status {status}")
