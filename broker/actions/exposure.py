"""Network exposure: the authoritative settings.

Everything here reduces what this PC will talk to, answer, or believe on a
network. None of it affects reaching out to the internet.

The guard rails in `guards.py` cover this family specifically: Balanced and
Strict both switch off Remote Desktop, and doing that from inside a Remote
Desktop session ends the session with no way back. `RDP_DISABLED_FROM` in the
guard names the same two levels this module disables it at, so the two cannot
drift apart.
"""

from ._common import Feature, Reg, Service, apply_settings

EXPLORER_POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
DNSCLIENT_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
DNSCACHE = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
TERMINAL_SERVER = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
LANMAN_WORKSTATION = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
LANMAN_SERVER = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
INTERNET_SETTINGS = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"

# 0xFF = disable AutoRun on every drive type, including network and removable.
NO_DRIVE_TYPE_AUTORUN_ALL = 0xFF

_BASIC = [
    # -- AutoRun --------------------------------------------------------------
    # The plug-in-a-USB-stick-and-it-runs route. Both values are needed: the
    # first covers drive types, the second the AutoRun command itself.
    Reg("HKLM", EXPLORER_POLICY, "NoDriveTypeAutoRun", "REG_DWORD", NO_DRIVE_TYPE_AUTORUN_ALL),
    Reg("HKLM", EXPLORER_POLICY, "NoAutorun", "REG_DWORD", 1),

    # -- SMBv1 ----------------------------------------------------------------
    # Thirty years old, the vehicle for WannaCry and NotPetya. Removed as a
    # Windows feature rather than merely disabled, so it cannot be turned back
    # on by something else.
    Feature("SMB1Protocol", enabled=False),
    Reg("HKLM", LANMAN_SERVER, "SMB1", "REG_DWORD", 0),

    Service("RemoteRegistry", "Disabled"),
]

_BALANCED = [
    # -- local name resolution ------------------------------------------------
    # LLMNR, mDNS and NetBIOS make this PC broadcast the name it is looking for
    # and trust whichever machine answers first. This is the standard way a
    # laptop on a shared network is tricked into handing over a password hash.
    Reg("HKLM", DNSCLIENT_POLICY, "EnableMulticast", "REG_DWORD", 0),
    Reg("HKLM", DNSCACHE, "EnableMDNS", "REG_DWORD", 0),

    # -- WPAD -----------------------------------------------------------------
    # Proxy auto-discovery asks the network where to send all your web traffic
    # and believes the answer.
    Reg("HKLM", INTERNET_SETTINGS, "DisableWpad", "REG_DWORD", 1),

    # -- SMB signing ----------------------------------------------------------
    # Without this a share connection can be silently relayed to another server.
    Reg("HKLM", LANMAN_WORKSTATION, "RequireSecuritySignature", "REG_DWORD", 1),
    Reg("HKLM", LANMAN_WORKSTATION, "EnableSecuritySignature", "REG_DWORD", 1),
    Reg("HKLM", LANMAN_SERVER, "RequireSecuritySignature", "REG_DWORD", 1),
    Reg("HKLM", LANMAN_SERVER, "EnableSecuritySignature", "REG_DWORD", 1),
    # Refuse to hand credentials to a server that claims it cannot do signing.
    Reg("HKLM", LANMAN_WORKSTATION, "EnablePlainTextPassword", "REG_DWORD", 0),

    # -- remote access --------------------------------------------------------
    # Guarded: refused outright if this session is itself a Remote Desktop
    # session. See guards.RDP_DISABLED_FROM.
    Reg("HKLM", TERMINAL_SERVER, "fDenyTSConnections", "REG_DWORD", 1),
    Service("TermService", "Disabled"),
    Service("WinRM", "Disabled"),
]

_STRICT = [
    # NetBIOS over TCP/IP off across every interface, and the firewall's default
    # inbound action set to Block on all three profiles. Both are applied
    # through PowerShell in `apply` below rather than as registry values,
    # because both are per-interface or per-profile enumerations.
]

LEVELS = {"basic": _BASIC, "balanced": _BALANCED, "strict": _STRICT}

# Kept in step with guards.RDP_DISABLED_FROM by a test: the guard must refuse at
# exactly the levels this module actually disables Remote Desktop at.
DISABLES_RDP_AT = ("balanced", "strict")


def apply(txn, level, ctx):
    applied = apply_settings(txn, ctx, LEVELS, level)
    extra = {}

    if level == "strict" and ctx.runner is not None:
        # Enumerated rather than declared: the interface list and the profile
        # list are both discovered at runtime, so these cannot be a static
        # table of registry values.
        ctx.runner("set-toggle.ps1", {"Toggle": "netbios", "State": "off"})
        for profile_toggle in ("firewall-domain", "firewall-private", "firewall-public"):
            ctx.runner("set-toggle.ps1", {"Toggle": profile_toggle, "State": "on"})
        ctx.runner("set-toggle.ps1", {"Toggle": "inbound-block", "State": "on"})
        extra["inboundBlocked"] = True

    return {
        "settingsApplied": len(applied),
        "notes": {"rdpDisabled": level in DISABLES_RDP_AT, **extra},
    }


def revert(txn, ctx):
    if ctx.runner is not None:
        try:
            ctx.runner("set-toggle.ps1", {"Toggle": "inbound-block", "State": "off"})
        except Exception:  # noqa: BLE001 - the journal still restores the rest
            pass
    return {}


def set_toggle(toggle, enabled, ctx):
    """Individual switches from the Hardening page, outside any level.

    `toggle` has already been checked against the protocol's fixed list, so this
    passes it straight through -- there is nothing further to validate that
    `protocol.validate_request` has not already done.
    """
    if ctx.runner is None:
        raise RuntimeError("no PowerShell runner is available")
    return ctx.runner("set-toggle.ps1", {"Toggle": toggle, "State": "on" if enabled else "off"})


def status(ctx):
    registry = ctx.registry

    def read(path, name):
        existed, _type, value = registry.read_value("HKLM", path, name)
        return value if existed else None

    live = {
        "autoRunDisabled": read(EXPLORER_POLICY, "NoDriveTypeAutoRun"),
        "llmnrDisabled": read(DNSCLIENT_POLICY, "EnableMulticast"),
        "mdnsDisabled": read(DNSCACHE, "EnableMDNS"),
        "wpadDisabled": read(INTERNET_SETTINGS, "DisableWpad"),
        "smbClientSigning": read(LANMAN_WORKSTATION, "RequireSecuritySignature"),
        "smbServerSigning": read(LANMAN_SERVER, "RequireSecuritySignature"),
        "rdpDenied": read(TERMINAL_SERVER, "fDenyTSConnections"),
    }
    if ctx.runner is not None:
        try:
            payload = ctx.runner("status-services.ps1") or {}
            live["services"] = payload.get("services")
            live["features"] = payload.get("features")
        except Exception as e:  # noqa: BLE001
            live["servicesError"] = str(e)
    return live
