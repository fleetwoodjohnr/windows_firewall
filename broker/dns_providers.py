"""Resolver identities and their addresses.

Shared reference data, like `asr_catalog`. The GUI sends a provider *id* from
`protocol.PROVIDERS` and never an address, so this table -- held on the
privileged side -- is what decides where lookups actually go. A compromised GUI
process cannot point the machine's DNS at a server of its choosing.

The `template` is the DoH URI. Windows 11 ships well-known templates for
Cloudflare, Google and Quad9; Mullvad and AdGuard have to be registered with
`Add-DnsClientDohServerAddress` before an interface can use them, which
`set-dns-provider.ps1` does.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    ipv4: tuple
    ipv6: tuple
    template: str
    detail: str


PROVIDERS = (
    Provider(
        id="automatic",
        label="Automatic — whatever the network gives you",
        ipv4=(), ipv6=(), template="",
        detail=(
            "Keep using the resolver handed out by whichever network or VPN you are connected to. "
            "Only the protection level changes; nothing is pinned.\n\n"
            "This is the right choice while a VPN is up. The tunnel resolves names at the far end, so "
            "your lookups stay inside it — pinning a public resolver instead would send them out "
            "around the tunnel, telling that provider, and everyone between you and it, exactly which "
            "sites you visit while you believe you are private."
        ),
    ),
    Provider(
        id="quad9",
        label="Quad9 — blocks known-malicious domains",
        ipv4=("9.9.9.9", "149.112.112.112"),
        ipv6=("2620:fe::fe", "2620:fe::9"),
        template="https://dns.quad9.net/dns-query",
        detail=(
            "Run by a Swiss non-profit. Quad9 simply refuses to answer for domains on a shared "
            "threat-intelligence list, so a phishing link or a malware callback fails at the lookup — "
            "before this PC ever opens a connection to it. That is a real layer of protection no "
            "firewall rule gives you, and it works for every program on the machine rather than just "
            "the browser.\n\n"
            "No personal data logged, and Swiss privacy law applies. Marginally slower than "
            "Cloudflare, and very occasionally it blocks something you actually wanted."
        ),
    ),
    Provider(
        id="cloudflare",
        label="Cloudflare — fastest, filters nothing",
        ipv4=("1.1.1.1", "1.0.0.1"),
        ipv6=("2606:4700:4700::1111", "2606:4700:4700::1001"),
        template="https://cloudflare-dns.com/dns-query",
        detail=(
            "Usually the fastest resolver available from most places, with servers nearly "
            "everywhere.\n\n"
            "It filters nothing at all: you get the honest answer for every domain, malicious ones "
            "included. That is a feature if you want DNS to stay out of the way, and a gap if you "
            "wanted the malware blocking that Quad9 or AdGuard provide. US company, with published "
            "third-party audits of its no-logging claims."
        ),
    ),
    Provider(
        id="mullvad",
        label="Mullvad — privacy-first, blocks ads and trackers",
        ipv4=("194.242.2.2",),
        ipv6=("2a07:e340::2",),
        template="https://dns.mullvad.net/dns-query",
        detail=(
            "Run by the Swedish VPN company and free to use without an account, a payment, or any "
            "identifier at all. Blocks ads and trackers as well as resolving names. Their whole "
            "business is built on not keeping records, and they have been audited on it.\n\n"
            "The smallest operator of the four, so a long way from Europe expect lookups to be a "
            "little slower than Cloudflare or Quad9."
        ),
    ),
    Provider(
        id="adguard",
        label="AdGuard — blocks ads and trackers everywhere",
        ipv4=("94.140.14.14", "94.140.15.15"),
        ipv6=("2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
        template="https://dns.adguard-dns.com/dns-query",
        detail=(
            "Blocks ad and tracker domains for every program on this PC, not just the browser — so it "
            "covers what a browser extension cannot reach, like telemetry from desktop applications "
            "and anything running in the background.\n\n"
            "The trade is the usual one for aggressive blocking: now and then a site loads its images "
            "or its checkout flow from a domain on the blocklist and half-breaks. If a site "
            "misbehaves, this is the first thing to switch off."
        ),
    ),
)

BY_ID = {provider.id: provider for provider in PROVIDERS}


def get(provider_id):
    return BY_ID.get(provider_id, BY_ID["automatic"])
