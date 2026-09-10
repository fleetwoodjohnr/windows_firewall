"""Credential protection: the authoritative settings.

Three tiers of increasingly serious protection for the secrets held on this PC:
tighten UAC and stop caching plaintext passwords; make lsass.exe unreadable even
to Administrators; and finally move secrets into a hypervisor the OS cannot
reach.

The last of those has real hardware consequences and can leave a machine that
boots but has lost a peripheral, so it is Strict-only and the page copy says
exactly what it costs.
"""

from ._common import Reg, apply_settings

POLICIES = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
MSV = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
WDIGEST = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
DEVICE_GUARD = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
HVCI = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

# NTLMMinClientSec / NTLMMinServerSec: require NTLMv2 session security plus
# 128-bit encryption. 0x20000000 | 0x00080000 = 537395200.
NTLM_MIN_SEC = 537395200

_BASIC = [
    # -- User Account Control -------------------------------------------------
    # 2 = always prompt for consent on the secure desktop. The secure desktop is
    # the part that matters: without it another program can draw a convincing
    # fake prompt, or click the real one for you.
    Reg("HKLM", POLICIES, "ConsentPromptBehaviorAdmin", "REG_DWORD", 2),
    Reg("HKLM", POLICIES, "PromptOnSecureDesktop", "REG_DWORD", 1),
    Reg("HKLM", POLICIES, "EnableLUA", "REG_DWORD", 1),
    # Applies UAC to the built-in Administrator account too, which by default is
    # exempt -- an exemption worth closing on a personal machine.
    Reg("HKLM", POLICIES, "FilterAdministratorToken", "REG_DWORD", 1),
    # 1 = prompt standard users for credentials on the secure desktop; this
    # preserves the ability to approve the app through an administrator account.
    Reg("HKLM", POLICIES, "ConsentPromptBehaviorUser", "REG_DWORD", 1),

    # -- stop handing out information to unauthenticated callers --------------
    Reg("HKLM", LSA, "RestrictAnonymous", "REG_DWORD", 1),
    Reg("HKLM", LSA, "RestrictAnonymousSAM", "REG_DWORD", 1),
    Reg("HKLM", LSA, "EveryoneIncludesAnonymous", "REG_DWORD", 0),

    # -- WDigest --------------------------------------------------------------
    # Stores the password in memory in a form readable as plain text. It exists
    # only for authentication nothing has used since Server 2003, and it is the
    # first thing a credential dumper looks for.
    Reg("HKLM", WDIGEST, "UseLogonCredential", "REG_DWORD", 0),
]

_BALANCED = [
    # -- LSA Protection -------------------------------------------------------
    # lsass.exe becomes a protected process: even a program running as
    # Administrator cannot read its memory. This is what stops Mimikatz.
    # Takes effect at the next boot.
    Reg("HKLM", LSA, "RunAsPPL", "REG_DWORD", 2),

    # Only Administrators may query the SAM remotely. The SDDL string is
    # Microsoft's documented value for this setting, not one we composed.
    Reg("HKLM", LSA, "RestrictRemoteSAM", "REG_SZ", "O:BAG:BAD:(A;;RC;;;BA)"),

    # 5 = send NTLMv2 only, and refuse LM and NTLMv1 entirely.
    Reg("HKLM", LSA, "LmCompatibilityLevel", "REG_DWORD", 5),
    Reg("HKLM", MSV, "NTLMMinClientSec", "REG_DWORD", NTLM_MIN_SEC),
    Reg("HKLM", MSV, "NTLMMinServerSec", "REG_DWORD", NTLM_MIN_SEC),

    # Don't keep the last sign-in's credentials cached for offline use beyond a
    # single account -- cached verifiers are crackable offline.
    Reg("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "CachedLogonsCount", "REG_SZ", "1"),
]

_STRICT = [
    # -- Credential Guard -----------------------------------------------------
    # Secrets move into a virtualised environment the main OS cannot reach, even
    # once fully compromised. Needs UEFI, Secure Boot and hardware
    # virtualisation, and takes the hypervisor for itself -- which is why other
    # virtualisation software frequently stops working. Reboot required.
    Reg("HKLM", DEVICE_GUARD, "EnableVirtualizationBasedSecurity", "REG_DWORD", 1),
    # 1 = Secure Boot required. Deliberately not 3 (Secure Boot + DMA
    # protection): DMA protection is unavailable on a lot of otherwise capable
    # hardware, and requiring it there means VBS silently never starts.
    Reg("HKLM", DEVICE_GUARD, "RequirePlatformSecurityFeatures", "REG_DWORD", 1),
    Reg("HKLM", LSA, "LsaCfgFlags", "REG_DWORD", 2),
    Reg("HKLM", HVCI, "Enabled", "REG_DWORD", 1),
]

LEVELS = {"basic": _BASIC, "balanced": _BALANCED, "strict": _STRICT}

# Reboot is not cosmetic for these: until it happens, lsass is still readable
# and Credential Guard is not running. The page must not imply otherwise.
REBOOT_REQUIRED_FROM = ("balanced", "strict")


def apply(txn, level, ctx):
    applied = apply_settings(txn, ctx, LEVELS, level)

    from .system_state import capture
    capture(txn, ctx, 'guest')
    ctx.runner('set-toggle.ps1', {'Toggle': 'guest-account', 'State': 'off'})

    return {
        "settingsApplied": len(applied),
        "notes": {
            "rebootRequired": level in REBOOT_REQUIRED_FROM,
            "credentialGuard": level == "strict",
        },
    }


def revert(txn, ctx):
    return {"rebootRequired": True}


def status(ctx):
    registry = ctx.registry

    def read(hive, path, name):
        existed, _type, value = registry.read_value(hive, path, name)
        return value if existed else None

    return {
        "uacConsentPrompt": read("HKLM", POLICIES, "ConsentPromptBehaviorAdmin"),
        "uacSecureDesktop": read("HKLM", POLICIES, "PromptOnSecureDesktop"),
        "uacEnabled": read("HKLM", POLICIES, "EnableLUA"),
        "lsaProtection": read("HKLM", LSA, "RunAsPPL"),
        "wdigestPlaintext": read("HKLM", WDIGEST, "UseLogonCredential"),
        "lmCompatibilityLevel": read("HKLM", LSA, "LmCompatibilityLevel"),
        "vbsEnabled": read("HKLM", DEVICE_GUARD, "EnableVirtualizationBasedSecurity"),
        "credentialGuard": read("HKLM", LSA, "LsaCfgFlags"),
        "hvci": read("HKLM", HVCI, "Enabled"),
    }
