"""Curated explanations for Windows firewall rule groups.

Port of the Fedora app's `data/services_catalog.py`. Windows groups its built-in
inbound rules by display group -- "File and Printer Sharing", "Remote Desktop" --
and those groups are the closest thing it has to firewalld's named services.

Windows ships several hundred rules in dozens of groups, most of them belonging
to a single app. Curating all of them would be busywork, so this covers the ones
that actually matter for exposure and everything else gets the generic fallback,
which says honestly that it is app-specific rather than inventing a risk rating.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleGroupInfo:
    label: str
    summary: str
    recommendation: str
    risk: str        # "low" | "medium" | "high"
    category: str


CATALOG = {
    "File and Printer Sharing": RuleGroupInfo(
        label="File and Printer Sharing",
        summary="Lets other machines open shared folders and printers on this PC.",
        recommendation=(
            "Leave this off on any network you do not control. It is the single most useful "
            "thing for an attacker on the same WiFi to find open, and on a laptop that never "
            "shares anything it buys you nothing.\n\n"
            "Turn it on only for the Private profile, and only if other machines in your home "
            "actually open folders on this one."
        ),
        risk="high",
        category="File sharing",
    ),
    "Remote Desktop": RuleGroupInfo(
        label="Remote Desktop",
        summary="Lets you connect to this PC's desktop from another machine.",
        recommendation=(
            "One of the most attacked services on the internet. If you do not connect to this "
            "machine remotely, close it — and if you do, never expose it directly to the "
            "internet; reach it over a VPN instead."
        ),
        risk="high",
        category="Remote access",
    ),
    "Network Discovery": RuleGroupInfo(
        label="Network Discovery",
        summary="Announces this PC on the local network and looks for others.",
        recommendation=(
            "Uses the broadcast name protocols that are the standard route to collecting "
            "credentials on a shared network. Useful at home for finding printers and media "
            "devices; switch it off on any public or work network."
        ),
        risk="medium",
        category="Discovery",
    ),
    "Windows Remote Management": RuleGroupInfo(
        label="Windows Remote Management",
        summary="Remote PowerShell and management access to this PC.",
        recommendation=(
            "Powerful and rarely used on a personal machine. If you are not administering this "
            "PC remotely, there is no reason for it to be reachable."
        ),
        risk="high",
        category="Remote access",
    ),
    "Windows Management Instrumentation (WMI)": RuleGroupInfo(
        label="Windows Management Instrumentation (WMI)",
        summary="Lets other machines query and control this one through WMI.",
        recommendation=(
            "A favourite tool for moving sideways across a network once one machine is "
            "compromised. Close it unless something specific needs it."
        ),
        risk="high",
        category="Remote access",
    ),
    "Remote Service Management": RuleGroupInfo(
        label="Remote Service Management",
        summary="Lets other machines start and stop services on this PC.",
        recommendation="No reason for this to be open on a desktop.",
        risk="high",
        category="Remote access",
    ),
    "Remote Event Log Management": RuleGroupInfo(
        label="Remote Event Log Management",
        summary="Lets other machines read this PC's event logs.",
        recommendation="Useful in a managed fleet, pointless and revealing on a personal machine.",
        risk="medium",
        category="Remote access",
    ),
    "Remote Volume Management": RuleGroupInfo(
        label="Remote Volume Management",
        summary="Lets other machines manage this PC's disks and volumes.",
        recommendation="Close it. Remote disk management on a desktop is all risk and no benefit.",
        risk="high",
        category="Remote access",
    ),
    "Cast to Device functionality": RuleGroupInfo(
        label="Cast to Device",
        summary="Lets this PC send video and audio to TVs and speakers on the network.",
        recommendation=(
            "Opens inbound ports so devices can talk back. Fine on a home network you trust, "
            "worth closing on anything shared."
        ),
        risk="medium",
        category="Media",
    ),
    "mDNS": RuleGroupInfo(
        label="mDNS",
        summary="Multicast DNS — finds printers, speakers and cast devices by name.",
        recommendation=(
            "Convenient at home and a broadcast protocol that trusts whatever answers. The "
            "Network Exposure level switches it off from Balanced upward."
        ),
        risk="medium",
        category="Discovery",
    ),
    "Delivery Optimization": RuleGroupInfo(
        label="Delivery Optimization",
        summary="Shares Windows Update downloads with other PCs on the network.",
        recommendation=(
            "Saves bandwidth on a network with several Windows machines. On a single laptop it "
            "is inbound surface for no benefit."
        ),
        risk="medium",
        category="Updates",
    ),
    "Core Networking": RuleGroupInfo(
        label="Core Networking",
        summary="The traffic Windows itself needs to work: DHCP, IPv6, ICMP.",
        recommendation=(
            "Leave this alone. Disabling it does not harden the machine, it breaks its ability "
            "to use a network at all."
        ),
        risk="low",
        category="Essential",
    ),
    "Core Networking Diagnostics": RuleGroupInfo(
        label="Core Networking Diagnostics",
        summary="Lets Windows' own network troubleshooters work.",
        recommendation="Low risk, and switching it off makes network problems harder to diagnose.",
        risk="low",
        category="Essential",
    ),
}

# Groups that must not be casually switched off. Turning these off does not
# harden the machine; it breaks networking and then looks like a hardening bug.
ESSENTIAL = ("Core Networking", "Core Networking Diagnostics")


def describe(group_name):
    """Curated info if we have it, an honest generic description otherwise."""
    known = CATALOG.get(group_name)
    if known is not None:
        return known
    return RuleGroupInfo(
        label=group_name,
        summary="Inbound rules belonging to an installed application or Windows component.",
        recommendation=(
            "This group is not in this app's curated list, so there is no risk rating for it. "
            "It was almost certainly created by whatever program it is named after.\n\n"
            "The safe default for any group you do not recognise is off: if something stops "
            "working afterwards, this is the first place to look. Nothing here is permanent."
        ),
        risk="medium",
        category="Application",
    )


def is_essential(group_name):
    return group_name in ESSENTIAL
