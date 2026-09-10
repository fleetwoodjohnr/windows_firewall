"""Guard rails: the changes this app refuses to make, and why.

The Fedora app has exactly one of these, and it is the most important twenty
lines in the project. `find_ssh_key_owner()` exists so that "disable password
authentication" cannot be applied to a machine whose owner would then have no
way back in. The level still applies; that one directive is skipped, and the
page says so out loud.

Windows needs more of them, because more of its hardening is capable of locking
you out of your own computer:

  * Disabling Remote Desktop *from* a Remote Desktop session ends the session
    that is applying the change, and there is no way back short of physical
    access. This is the direct descendant of the SSH key guard.
  * Turning on BitLocker without its recovery key saved somewhere is how people
    permanently lose every file they have. A TPM change, a firmware update or a
    failed boot then asks for a key that was never written down.
  * Tamper Protection makes most Defender writes silently no-op. Applying a
    level that cannot take effect, and then reporting success, would be worse
    than doing nothing -- the user would believe they were protected.

A guard returns a refusal string, and refusing is not an error. The distinction
is carried in the response kind (`guard` versus `failed`) so the UI can present
it as the app looking after the user rather than as something going wrong.

Probing is injected rather than imported so every decision below is testable on
any platform. `WindowsProbes` is the real implementation; tests pass a stub.
"""

import os

from .protocol import ERR_BLOCKED, ERR_GUARD


class Probes:
    """What the guards need to know about the machine. Every method answers
    conservatively -- if we cannot tell, we assume the risky case is true, so an
    unknown never becomes a silent lockout."""

    def is_remote_session(self):
        raise NotImplementedError

    def bitlocker_recovery_key_saved(self):
        raise NotImplementedError

    def ssh_authorized_key_present(self):
        raise NotImplementedError

    def is_tamper_protected(self):
        raise NotImplementedError


class StubProbes(Probes):
    """For tests, and for the Linux development machine."""

    def __init__(self, remote=False, bitlocker_key=True, ssh_key=True, tamper=False):
        self._remote = remote
        self._bitlocker_key = bitlocker_key
        self._ssh_key = ssh_key
        self._tamper = tamper

    def is_remote_session(self):
        return self._remote

    def bitlocker_recovery_key_saved(self):
        return self._bitlocker_key

    def ssh_authorized_key_present(self):
        return self._ssh_key

    def is_tamper_protected(self):
        return self._tamper


class WindowsProbes(Probes):  # pragma: no cover - Windows-only
    """The real probes.

    `runner` runs one of the shipped read-only PowerShell scripts and returns its
    parsed JSON, so nothing here builds a command line of its own.
    """

    def __init__(self, runner):
        self._run = runner
        self._cache = {}

    def _status(self, script):
        if script not in self._cache:
            try:
                self._cache[script] = self._run(script) or {}
            except Exception:  # noqa: BLE001 - an unreadable probe must fail safe
                self._cache[script] = {}
        return self._cache[script]

    def refresh(self):
        self._cache.clear()

    def is_remote_session(self):
        try:
            import win32ts
            protocol = win32ts.WTSQuerySessionInformation(
                win32ts.WTS_CURRENT_SERVER_HANDLE, win32ts.WTS_CURRENT_SESSION,
                win32ts.WTSClientProtocolType)
            return protocol != 0
        except Exception:
            return True

    def bitlocker_recovery_key_saved(self):
        status = self._status("status-hardening.ps1")
        volumes = status.get("bitlocker") or []
        if not volumes:
            return False
        return all(bool(v.get("protectionOn")) and bool(v.get("recoveryProtectorPresent", v.get("recoveryKeySaved"))) for v in volumes)

    def ssh_authorized_key_present(self):
        return bool(self._status("status-services.ps1").get("sshAuthorizedKeyPresent"))

    def is_tamper_protected(self):
        status = self._status("status-defender.ps1")
        # Absent means Defender could not be read at all, which is itself a
        # reason not to claim a Defender level was applied.
        return bool(status.get("isTamperProtected", True))


# -- refusals -----------------------------------------------------------------

class Refusal:
    """A guard's decision: refuse, with a kind and user-facing prose."""

    def __init__(self, kind, message):
        self.kind = kind
        self.message = message


RDP_LOCKOUT = (
    "This would switch off Remote Desktop while you are connected over Remote Desktop, "
    "which ends this session immediately and leaves no way back in without physical "
    "access to the machine.\n\n"
    "Apply this from the computer itself, or turn off Remote Desktop last, once you no "
    "longer need remote access."
)

BITLOCKER_NO_KEY = (
    "Strict requires BitLocker protection with a recovery key protector present. "
    "The app could not verify those prerequisites. It does not enable encryption "
    "or verify that your recovery key has been backed up.\n\nOpen Windows Settings "
    "to configure encryption and save your recovery key before retrying."
)

TAMPER_PROTECTED = (
    "Tamper Protection is on, so Windows is rejecting changes to Microsoft Defender's "
    "settings. Applying this level would appear to work and silently change nothing, which "
    "is worse than not applying it, so it has been refused.\n\n"
    "Turn Tamper Protection off in Windows Security > Virus & threat protection > Manage "
    "settings, apply this level, and switch it back on afterwards. Windows does not allow "
    "any application to turn it off for you -- that is the point of it."
)


# Families whose levels are written through Microsoft Defender, and which
# Tamper Protection therefore blocks.
DEFENDER_BACKED_FAMILIES = ("defender", "exploit")

# Families whose levels switch off Remote Desktop.
RDP_DISABLING_FAMILIES = ("exposure",)

# The level at which the exposure family starts disabling Remote Desktop. Kept
# next to the guard rather than inside the action module so the guard cannot
# drift out of step with what it is guarding.
RDP_DISABLED_FROM = ("balanced", "strict")


def check(request, probes):
    """Return a Refusal, or None to allow.

    Called for every privileged request before any action module runs, so there
    is one place to look for "what will this app refuse to do".
    """
    verb = request["verb"]

    if verb == 'set-toggle' and request['toggle'] == 'panic-mode' and request['enabled']:
        if probes.is_remote_session():
            return Refusal(ERR_GUARD, 'Panic mode would disconnect this remote session. Apply it at the computer itself.')

    if verb == "set-toggle" and request["toggle"] == "rdp" and request["enabled"] is False:
        if probes.is_remote_session():
            return Refusal(ERR_GUARD, RDP_LOCKOUT)

    if verb == "apply":
        family = request["family"]
        level = request["level"]

        if family in DEFENDER_BACKED_FAMILIES and level != "off" and probes.is_tamper_protected():
            return Refusal(ERR_BLOCKED, TAMPER_PROTECTED)

        if family in RDP_DISABLING_FAMILIES and level in RDP_DISABLED_FROM:
            if probes.is_remote_session():
                return Refusal(ERR_GUARD, RDP_LOCKOUT)

        if family == "exploit" and level == "strict" and not probes.bitlocker_recovery_key_saved():
            return Refusal(ERR_GUARD, BITLOCKER_NO_KEY)

    if verb == "set-asr" and request["asr_action"] != "off" and probes.is_tamper_protected():
        return Refusal(ERR_BLOCKED, TAMPER_PROTECTED)

    return None
