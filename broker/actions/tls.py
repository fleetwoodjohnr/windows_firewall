"""TLS and cryptography: the authoritative settings.

The genuine Windows analogue of Fedora's `update-crypto-policies`. SCHANNEL is
the component every Windows program uses for TLS, so changing its floor changes
it for Windows Update, Office, .NET applications, Edge and anything else asking
the OS to make an encrypted connection. Chrome and Firefox ship their own TLS
stacks and are only partly affected -- the page copy says so.

Two Windows details that are easy to get wrong, and the reason these tables are
generated at authoring time rather than hand-typed:

  * A protocol is only actually off when BOTH `Enabled=0` and
    `DisabledByDefault=1` are set, separately for Client and Server. Setting one
    without the other leaves it reachable, and the machine looks hardened while
    it is not.
  * `SchUseStrongCrypto` has to be written under Wow6432Node as well, or 32-bit
    .NET applications keep their own weaker defaults on a 64-bit machine.

Levels declare what they ADD; `cumulative()` composes them, and a higher level
re-declaring a value overrides the lower one.
"""

from ._common import Reg, apply_settings

SCHANNEL = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# -- basic: switch off what has been broken for a decade ----------------------
_BASIC = [
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client", "Enabled", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client", "DisabledByDefault", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server", "Enabled", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server", "DisabledByDefault", "REG_DWORD", 0),
    # 32-bit .NET on a 64-bit machine reads Wow6432Node, and keeps its own
    # weaker defaults if only the 64-bit key is written. Missing this half is
    # the most common mistake in .NET TLS hardening.
    Reg("HKLM", r"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto", "REG_DWORD", 1),
    Reg("HKLM", r"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", "REG_DWORD", 1),
    Reg("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto", "REG_DWORD", 1),
    Reg("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", "REG_DWORD", 1),
]

# -- balanced: require TLS 1.2 or better --------------------------------------
_BALANCED = [
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "DisabledByDefault", "REG_DWORD", 1),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168", "Enabled", "REG_DWORD", 0),
]

# -- strict: weak hashes out as well ------------------------------------------
_STRICT = [
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5", "Enabled", "REG_DWORD", 0),
    Reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA", "Enabled", "REG_DWORD", 0),
]

LEVELS = {"basic": _BASIC, "balanced": _BALANCED, "strict": _STRICT}


def apply(txn, level, ctx):
    applied = apply_settings(txn, ctx, LEVELS, level)
    return {
        "settingsApplied": len(applied),
        "notes": {
            # Surfaced by the page: a crypto floor takes effect per-program at
            # next start, so "applied" does not yet mean "in force everywhere".
            "rebootRecommended": True,
        },
    }


def revert(txn, ctx):
    # Nothing to undo beyond the journal: every change is a registry value, and
    # replaying the journal restores each one exactly.
    return {"rebootRecommended": True}


def status(ctx):
    """Read the live floor back out of SCHANNEL.

    Reports what the registry actually says rather than what we believe we
    wrote, so a value changed by group policy or by hand shows up as a
    disagreement on the page instead of being hidden.
    """
    registry = ctx.registry
    protocols = {}
    for name in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"):
        sides = {}
        for side in ("Client", "Server"):
            existed, _type, value = registry.read_value(
                "HKLM", f"{SCHANNEL}\\Protocols\\{name}\\{side}", "Enabled")
            # Absent means "Windows default", which differs per protocol and per
            # Windows version -- reported as None rather than guessed.
            sides[side.lower()] = None if not existed else bool(value)
        protocols[name] = sides

    existed, _type, strong = registry.read_value(
        "HKLM", r"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto")
    return {
        "protocols": protocols,
        "dotnetStrongCrypto": bool(strong) if existed else None,
    }
