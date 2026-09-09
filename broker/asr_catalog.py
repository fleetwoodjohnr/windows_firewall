"""Attack Surface Reduction rules: the verified table.

Every GUID here was read from Microsoft's ASR rules reference on 2026-09-09,
not recalled:
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

That mattered. A wrong GUID does not error -- `Set-MpPreference` accepts it and
the rule silently does nothing, so the app would report protection the machine
does not have. Checking cost one page fetch; getting it wrong would have been
invisible.

Several things in this table also contradict the common summary of ASR:

  * ASR works on **every** Windows edition that has Defender, Windows 11 Home
    included. No E5 licence is needed for the rules themselves -- only for
    centralised reporting, which a single desktop does not use.
  * **Warn mode is not universal.** Two rules support only Off/Audit/Block, so
    a UI offering four states for every rule would be lying about two of them.
  * Three rules **require cloud-delivered protection** to be on. Enabling them
    without it produces a rule that is configured and inert, which is why the
    defender family raises cloud protection before it touches these.
  * The LSASS rule is **redundant once LSA Protection is on** -- Microsoft says
    so directly. The credential family turns LSA Protection on, so the two
    families interact and the copy says which one to prefer.
  * Real, named incompatibilities exist (BeyondTrust, Heimdal, Quest Dirsync).
    They are recorded per rule and surfaced in the UI rather than discovered by
    the user when something breaks.

This module is shared by the broker and the GUI. It is reference data, not an
instruction, so there is one copy rather than a mirror -- the same reasoning
that lets both sides import `protocol.py`.
"""

from dataclasses import dataclass, field

# Set-MpPreference's ASRRuleActionType. Our protocol's action ids map onto these.
ACTION_TO_MP = {
    "off": "Disabled",
    "audit": "AuditMode",
    "warn": "Warn",
    "block": "Enabled",
}

# What Get-MpPreference reports back, as integers.
MP_TO_ACTION = {0: "off", 1: "block", 2: "audit", 6: "warn"}


@dataclass(frozen=True)
class AsrRule:
    guid: str
    name: str
    summary: str
    detail: str
    breaks: str
    supports_warn: bool = True
    needs_cloud: bool = False
    desktop_relevant: bool = True
    incompatibilities: tuple = field(default_factory=tuple)


RULES = (
    # -- standard protection --------------------------------------------------
    AsrRule(
        guid="56a863a9-875e-4185-98a7-b882c64b5ce5",
        name="Block abuse of exploited vulnerable signed drivers",
        summary="Stops malware installing a legitimately-signed but buggy driver to get into the kernel.",
        detail=(
            "Attackers who already have Administrator rights cannot normally reach the kernel, because "
            "Windows only loads signed drivers. The workaround they use is to install someone else's "
            "signed driver that has a known hole in it, and drive through that hole — which is how most "
            "security software gets switched off before ransomware runs. This rule blocks writing such "
            "drivers to disk.\n\n"
            "It does not unload drivers already installed."
        ),
        breaks="Almost nothing on a desktop. Occasionally an old hardware utility that ships its own driver.",
    ),
    AsrRule(
        guid="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        name="Block credential stealing from lsass.exe",
        summary="Blocks reading the process that holds your passwords in memory. What Mimikatz does.",
        detail=(
            "lsass.exe holds credentials for everyone signed in. Reading its memory is the single most "
            "common way an attacker turns one compromised machine into the whole network.\n\n"
            "Microsoft is explicit that this rule is unnecessary once LSA Protection is switched on, and "
            "LSA Protection is the stronger of the two. The Hardening page's Credential Theft level turns "
            "that on. Use this rule if you cannot enable LSA Protection — for example because a smartcard "
            "driver refuses to load under it."
        ),
        breaks=(
            "Nothing functional, but it is noisy: many ordinary programs (Chrome's updater is the usual "
            "example) poke at lsass for no good reason and get blocked from doing so without breaking. "
            "Microsoft recommends going straight to Block rather than sitting in Audit reading those."
        ),
        supports_warn=False,
        incompatibilities=("Quest Dirsync Password Sync",),
    ),
    AsrRule(
        guid="e6db77e5-3df2-4cf1-b95a-636979351e5b",
        name="Block persistence through WMI event subscription",
        summary="Closes a hiding place that survives reboots and leaves nothing in the file system.",
        detail=(
            "WMI can be told to run a command whenever some system event happens. Malware uses this to "
            "come back after every reboot while storing nothing on disk, which defeats file-based "
            "scanning entirely."
        ),
        breaks="Nothing on a normal desktop. Enterprise management agents sometimes use WMI subscriptions.",
    ),
    # -- everything else ------------------------------------------------------
    AsrRule(
        guid="be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        name="Block executable content from email and webmail",
        summary="Stops programs and scripts arriving by email from running at all.",
        detail=(
            "Blocks executables, scripts and archives that came from Outlook or a webmail site from "
            "being launched. This is the oldest malware delivery route there is and it still works, "
            "because it relies on a person rather than a vulnerability."
        ),
        breaks=(
            "If a colleague emails you a legitimate installer or script, it will not run from the "
            "attachment. Save it, check it, and run it from Downloads instead."
        ),
    ),
    AsrRule(
        guid="d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        name="Block Office applications from creating child processes",
        summary="A Word document cannot start PowerShell. Closes the classic macro attack.",
        detail=(
            "Malicious Office documents work by having a macro launch something else — PowerShell, cmd, "
            "mshta — to fetch the real payload. This rule severs that step, which breaks the great "
            "majority of document-borne attacks regardless of what the macro contains."
        ),
        breaks=(
            "Line-of-business spreadsheets that shell out to a script or a command. Rare at home, "
            "common in finance teams. Only enforced when Office is installed in Program Files."
        ),
    ),
    AsrRule(
        guid="3b576869-a4ec-4529-8536-b80a7769e899",
        name="Block Office applications from creating executable content",
        summary="Office cannot write a program to disk for something else to run later.",
        detail=(
            "Stops Word, Excel and PowerPoint saving executable files, which is how document malware "
            "gets a payload onto the disk where it can survive a reboot."
        ),
        breaks="Rare. A document-driven workflow that generates a program file.",
    ),
    AsrRule(
        guid="75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        name="Block Office applications from injecting code into other processes",
        summary="No legitimate reason exists to do this. Blocking it costs nothing.",
        detail=(
            "Code injection lets a malicious macro run inside a process that looks trustworthy. "
            "Microsoft states plainly that there is no known legitimate business use for Office doing "
            "this, which makes it one of the cheapest rules to enable."
        ),
        breaks=(
            "Nothing, with two known exceptions: BeyondTrust Privilege Guard and Heimdal security are "
            "documented as incompatible. Office applications need restarting for it to take effect."
        ),
        supports_warn=False,
        incompatibilities=("BeyondTrust Privilege Guard", "Heimdal Security"),
    ),
    AsrRule(
        guid="26190899-1602-49e8-8b27-eb1d0a1ce869",
        name="Block Outlook from creating child processes",
        summary="Blocks the Outlook rules-and-forms trick used after a mailbox is compromised.",
        detail=(
            "Once someone has your mailbox password they can plant an Outlook rule or form that runs a "
            "program the next time Outlook starts — persistence that survives a password reset because "
            "it lives in the mailbox, not on the PC."
        ),
        breaks="Outlook add-ins that launch helper programs.",
    ),
    AsrRule(
        guid="92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        name="Block Win32 API calls from Office macros",
        summary="Stops macros calling straight into Windows to run code without touching disk.",
        detail=(
            "VBA can call Win32 APIs directly, which lets a macro allocate memory and execute shellcode "
            "without ever writing a file for a scanner to find. Very few macros legitimately need this."
        ),
        breaks="Sophisticated macros that call Windows APIs — uncommon, but they do exist.",
    ),
    AsrRule(
        guid="d3e037e1-3eb8-44c8-a917-57927947596d",
        name="Block JavaScript and VBScript from launching downloaded executables",
        summary="Breaks the download-and-run pattern of script droppers.",
        detail=(
            "A .js or .vbs file arriving in a zip, whose only job is to download the real malware and "
            "start it. This rule blocks the second half of that."
        ),
        breaks="Occasionally an installer that uses a script to fetch its own payload.",
    ),
    AsrRule(
        guid="5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        name="Block execution of potentially obfuscated scripts",
        summary="Deliberately unreadable scripts are refused. Works on PowerShell too.",
        detail=(
            "Uses AMSI to inspect scripts as they run and blocks ones showing the hallmarks of "
            "deliberate obfuscation — the encoding and string-mangling used to hide intent from both "
            "a reader and a scanner."
        ),
        breaks=(
            "Some commercial software ships minified or packed scripts that look obfuscated because "
            "they effectively are. Audit first if you use unusual tooling."
        ),
        needs_cloud=True,
    ),
    AsrRule(
        guid="01443614-cd74-433a-b99e-2ecdc07bfc25",
        name="Block executables that are not prevalent, aged or trusted",
        summary="A program nobody else in the world has run yet does not get to run here.",
        detail=(
            "Checks each executable against Microsoft's cloud for how common and how old it is. "
            "Targeted malware is by definition rare and new, so this catches attacks built "
            "specifically for you that no signature exists for."
        ),
        breaks=(
            "The most disruptive rule in the list. Freshly-built software, niche tools, your own "
            "compiled binaries and beta releases are all blocked for being unusual. Audit this one "
            "before enforcing it."
        ),
        needs_cloud=True,
    ),
    AsrRule(
        guid="c1db55ab-c21a-4637-bb3f-a12568109d35",
        name="Use advanced protection against ransomware",
        summary="Cloud and local heuristics on files that behave like ransomware.",
        detail=(
            "Judges files by behaviour and reputation rather than signature. Deliberately errs toward "
            "caution: it blocks files that have no positive reputation yet, not only ones with a bad "
            "one."
        ),
        breaks=(
            "New and uncommon software may be blocked until its reputation builds, which usually "
            "resolves by itself over days."
        ),
        needs_cloud=True,
    ),
    AsrRule(
        guid="d1e49aac-8f56-4280-b9ba-993a6d77406c",
        name="Block process creation from PSExec and WMI commands",
        summary="Closes the two tools most used to spread sideways across a network.",
        detail=(
            "PsExec and WMI both run commands on a remote machine. They are how one compromised PC "
            "becomes all of them. On a personal desktop neither is normally used."
        ),
        breaks=(
            "Remote administration of this PC using PsExec or WMI stops working. If you manage this "
            "machine remotely with either, leave this off."
        ),
    ),
    AsrRule(
        guid="b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        name="Block untrusted and unsigned processes from USB",
        summary="A program on a USB stick must be signed before it runs.",
        detail=(
            "Covers USB drives and SD cards. Copying the file to the hard disk is still allowed — it "
            "is running it that is blocked, from either location."
        ),
        breaks="Portable applications run from a USB stick, which are frequently unsigned.",
    ),
    AsrRule(
        guid="33ddedf1-c6e0-47cb-833e-de6133960387",
        name="Block rebooting the machine into Safe Mode",
        summary="Stops ransomware rebooting into Safe Mode where Defender is not running.",
        detail=(
            "Several ransomware families reboot into Safe Mode before encrypting, because most "
            "security software is disabled there. This blocks the commands that request it.\n\n"
            "Safe Mode is still reachable by hand from the Windows Recovery Environment, so this does "
            "not lock you out of recovery."
        ),
        breaks="Scripted reboots into Safe Mode using bcdedit or bootcfg.",
        supports_warn=True,
    ),
    AsrRule(
        guid="c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
        name="Block copied or impersonated system tools",
        summary="A renamed copy of a Windows tool is refused.",
        detail=(
            "Attackers copy or rename genuine Windows utilities to slip past rules that trust them by "
            "name and location. This blocks executables identified as duplicates or imposters of "
            "system tools."
        ),
        breaks="Rare. Software that bundles its own copy of a Windows utility.",
    ),
    AsrRule(
        guid="7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
        name="Block Adobe Reader from creating child processes",
        summary="A PDF cannot start another program.",
        detail=(
            "The same pattern as the Office rule, applied to Adobe Reader: a malicious PDF breaking out "
            "of the reader to launch a payload."
        ),
        breaks="Adobe Reader workflows that hand off to another application.",
    ),
    AsrRule(
        guid="a8f5898e-1dc8-49a9-9878-85004b8a61e6",
        name="Block web shell creation for servers",
        summary="Exchange servers only. Not applicable to a desktop.",
        detail=(
            "Blocks web shell scripts being written on a Windows server running Microsoft Exchange. "
            "Listed here for completeness; it does nothing on a desktop and is not offered by the "
            "Defender levels."
        ),
        breaks="Nothing on a desktop.",
        desktop_relevant=False,
    ),
)

BY_GUID = {rule.guid: rule for rule in RULES}

# What the level families enable, cumulatively. Chosen so that each step up is
# defensible on a personal desktop rather than an enterprise fleet -- the two
# rules with real false-positive potential (unusual executables, obfuscated
# scripts) arrive last and in Audit before they are enforced.
BASIC_RULES = (
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",  # email/webmail executables
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",  # Office child processes
    "3b576869-a4ec-4529-8536-b80a7769e899",  # Office executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",  # Office code injection
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",  # Win32 calls from macros
    "d3e037e1-3eb8-44c8-a917-57927947596d",  # JS/VBS launching downloads
    "26190899-1602-49e8-8b27-eb1d0a1ce869",  # Outlook child processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",  # Adobe Reader child processes
)

BALANCED_RULES = BASIC_RULES + (
    "56a863a9-875e-4185-98a7-b882c64b5ce5",  # vulnerable signed drivers
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",  # lsass credential theft
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",  # WMI persistence
    "c1db55ab-c21a-4637-bb3f-a12568109d35",  # advanced ransomware protection
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # untrusted USB processes
    "33ddedf1-c6e0-47cb-833e-de6133960387",  # safe mode reboot
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",  # impersonated system tools
)

# The two rules with real false-positive potential on a personal machine. They
# arrive at Balanced in Audit mode -- configured and reporting, but not blocking
# anything -- and are enforced only at Strict. Stepping up to Balanced therefore
# cannot suddenly stop a program the user depends on.
AUDIT_FIRST_RULES = (
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",  # obfuscated scripts
    "01443614-cd74-433a-b99e-2ecdc07bfc25",  # unusual executables
)

BALANCED_RULES = BALANCED_RULES + AUDIT_FIRST_RULES

STRICT_RULES = BALANCED_RULES + (
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # PsExec/WMI process creation
)


def action_for(rule_guid, level):
    """The action a level applies to one rule.

    Balanced audits the two false-positive-prone rules rather than enforcing
    them, so stepping up to Balanced cannot suddenly stop a program the user
    depends on. Strict enforces everything.
    """
    guid = rule_guid.lower().strip("{}")
    if level == "basic":
        return "block" if guid in BASIC_RULES else None
    if level == "balanced":
        if guid in AUDIT_FIRST_RULES:
            return "audit"
        return "block" if guid in BALANCED_RULES else None
    if level == "strict":
        return "block" if guid in STRICT_RULES else None
    return None


def desktop_rules():
    return tuple(rule for rule in RULES if rule.desktop_relevant)
