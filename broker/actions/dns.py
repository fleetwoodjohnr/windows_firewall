"""DNS privacy: the authoritative settings.

Two axes, deliberately kept apart because they use different mechanisms and fail
differently -- the same split the Fedora app made:

  * A *level* controls how lookups are protected: encrypted transport, and
    whether the local-network name protocols are allowed to shout. Machine-wide.
  * A *provider* controls who answers them. Per-interface, and chosen
    separately, because the right answer changes depending on whether a VPN is
    up.

An honest difference from Linux, stated in the page copy and repeated here so
nobody re-reads this module and "fixes" it: Windows has no client-side DNSSEC
validation equivalent to systemd-resolved's. Strict means DoH is mandatory with
no fallback -- encrypted transport to an authenticated server -- not
signature-validated answers. The Fedora copy's DNSSEC language does not carry
over and must not be reintroduced.
"""

from ._common import Reg, apply_settings

DNSCLIENT_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
DNSCACHE = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

# DoH auto-upgrade for the whole machine. 2 = require DoH, no fallback to
# unencrypted; 1 = use it where available and fall back otherwise.
DOH_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

_BASIC = [
    # Auto-upgrade to DoH where the resolver is known to support it, with
    # fallback still allowed. Strictly better than off on networks that support
    # encryption, and identical to off on the ones that do not.
    Reg("HKLM", DOH_POLICY, "DoHPolicy", "REG_DWORD", 2),
]

_BALANCED = [
    # The local-network name protocols. These make the PC broadcast the name it
    # is looking for and trust whichever machine answers first -- the standard
    # route to collecting credentials on a shared network.
    #
    # The Network Exposure family sets these same two values at its own Balanced
    # level. Applying both families is harmless: they write identical values,
    # and whichever journals first holds the true original.
    Reg("HKLM", DNSCLIENT_POLICY, "EnableMulticast", "REG_DWORD", 0),
    Reg("HKLM", DNSCACHE, "EnableMDNS", "REG_DWORD", 0),
]

_STRICT = [
    # 3 = require DoH. A lookup that cannot be encrypted is refused rather than
    # downgraded. This is the value that breaks captive portals, which is said
    # plainly in the level copy rather than discovered in a hotel.
    Reg("HKLM", DOH_POLICY, "DoHPolicy", "REG_DWORD", 3),
]

LEVELS = {"basic": _BASIC, "balanced": _BALANCED, "strict": _STRICT}


def apply(txn, level, ctx):
    applied = apply_settings(txn, ctx, LEVELS, level)
    return {
        "settingsApplied": len(applied),
        "notes": {
            # Strict without a DoH-capable resolver pinned means no name
            # resolution at all on many networks. The page uses this to insist
            # on a provider before offering Strict.
            "requiresPinnedResolver": level == "strict",
        },
    }


def revert(txn, ctx):
    return {}


def set_provider(provider_id, interface_index, ctx):
    """Pin (or unpin) one interface's resolver.

    `provider_id` is an id from the protocol's fixed list, never an address:
    `set-dns-provider.ps1` looks the addresses up from `dns_providers` on the
    privileged side.
    """
    if ctx.runner is None:
        raise RuntimeError("no PowerShell runner is available")
    return ctx.runner("set-dns-provider.ps1", {
        "InterfaceIndex": str(int(interface_index)),
        "Provider": provider_id,
    })


def status(ctx):
    registry = ctx.registry

    def read(path, name):
        existed, _type, value = registry.read_value("HKLM", path, name)
        return value if existed else None

    live = {
        "dohPolicy": read(DOH_POLICY, "DoHPolicy"),
        "llmnrDisabled": read(DNSCLIENT_POLICY, "EnableMulticast"),
        "mdnsDisabled": read(DNSCACHE, "EnableMDNS"),
    }
    if ctx.runner is not None:
        try:
            payload = ctx.runner("status-network.ps1") or {}
            live["interfaces"] = payload.get("interfaces")
        except Exception as e:  # noqa: BLE001
            live["interfacesError"] = str(e)
    return live
