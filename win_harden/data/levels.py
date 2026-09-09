"""Plain-English copy for the six hardening level families.

This is the display half. The settings each level actually writes live in
`broker/actions/`, and the broker never reads this file -- it takes a level id
and looks the meaning up itself.

The Fedora app kept a full mirror of the helper's settings here and warned that
the two would drift (`data/encryption_levels.py:14-18`). This port does not
mirror them at all: prose here, settings there, one copy of each. The trust
property is unchanged -- the GUI still sends only a level id -- but there is now
nothing to fall out of step. A test checks that both sides agree on the set of
family and level ids, which is all that is left to disagree about.

Writing rules for `breaks`, inherited from the original and worth restating:

  * Say what will actually stop working, in the words of someone who will hit
    it. "Older HTTPS sites and printer web interfaces" beats "reduced
    compatibility".
  * Never claim a level is free if it isn't. Strict is supposed to sound like a
    commitment, because it is one.
  * Where the honest answer is "nothing", say nothing -- and mean it.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Level:
    id: str
    label: str
    summary: str
    detail: str
    breaks: str


@dataclass(frozen=True)
class Family:
    id: str
    title: str
    subtitle: str
    levels: tuple
    footnote: str = ""

    def level(self, level_id):
        for level in self.levels:
            if level.id == level_id:
                return level
        return self.levels[0]


_OFF_BOILERPLATE = (
    "Everything this family changed is put back exactly as it was found. Values that existed "
    "before are restored to their old contents; values this app created are deleted rather than "
    "set to a guessed default, so the machine ends up indistinguishable from one this app never "
    "touched."
)


# -- Defender & ASR -----------------------------------------------------------

DEFENDER = Family(
    id="defender",
    title="Microsoft Defender & Attack Surface Reduction",
    subtitle="Antivirus settings, cloud protection, and the rules that block how malware behaves.",
    footnote=(
        "Attack Surface Reduction rules work on every edition of Windows that has Defender, "
        "Windows 11 Home included — no enterprise licence is needed. Three of the rules only "
        "function when cloud-delivered protection is on, which is why every level from Basic "
        "upward turns that on first.\n\n"
        "Tamper Protection must be off while these are applied. Windows does not allow any "
        "application to turn it off — that is the whole point of it — so if it is on, the "
        "Protection page will say so and refuse rather than appear to work and change nothing."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "Defender runs as Windows ships it: real-time protection on, cloud protection at its "
                "default level, no Attack Surface Reduction rules configured, and potentially unwanted "
                "applications allowed through.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing breaks, because nothing changes — but the machine is relying on signature "
                "detection alone. Every technique the ASR rules block, from macro droppers to lsass "
                "credential theft, is available to anything that gets onto this PC."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Cloud protection on, adware blocked, and the document-malware rules enforced.",
            detail=(
                "Turns cloud-delivered protection up to Advanced with automatic submission of safe "
                "samples, so an unknown file is judged against what Microsoft is seeing globally rather "
                "than only against yesterday's signatures. Switches on protection against potentially "
                "unwanted applications — the bundled toolbars, fake optimisers and adware that "
                "technically are not viruses and that ordinary antivirus deliberately ignores.\n\n"
                "Then it enforces eight ASR rules, all of them aimed at documents and email: Office "
                "cannot launch other programs, write executables, or inject code; macros cannot call "
                "Windows APIs directly; scripts arriving by email cannot run; Outlook and Adobe Reader "
                "cannot start child processes."
            ),
            breaks=(
                "For almost everyone, nothing. The exceptions are specific: a spreadsheet that shells "
                "out to a script or command will stop working, and an installer emailed to you will no "
                "longer run straight from the attachment — save it and run it from Downloads instead.\n\n"
                "If BeyondTrust Privilege Guard or Heimdal Security is installed, the Office code "
                "injection rule is documented as incompatible with both; turn that one rule off "
                "individually on the Protection page."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Adds credential, ransomware, driver and USB protection. The daily driver.",
            detail=(
                "Everything in Basic, plus seven more rules covering the ways an attacker escalates "
                "once they are already running: reading credentials out of lsass.exe, installing a "
                "vulnerable signed driver to reach the kernel, hiding in a WMI event subscription, "
                "running unsigned programs off a USB stick, impersonating a Windows system tool, and "
                "rebooting into Safe Mode where Defender is not running. Advanced ransomware "
                "heuristics are enabled alongside them, and the cloud block level is raised to High.\n\n"
                "Two further rules — obfuscated scripts, and executables too new or too rare to have a "
                "reputation — are switched on in Audit mode. They report what they would have blocked "
                "without blocking it, so you can see whether they would disrupt anything before Strict "
                "enforces them."
            ),
            breaks=(
                "Little, and mostly noise rather than breakage. The lsass rule logs a great many "
                "blocked-but-harmless events — Chrome's updater is the usual culprit — which is "
                "expected and safe to ignore.\n\n"
                "Real effects: portable applications on USB sticks are often unsigned and will not run, "
                "and scripted reboots into Safe Mode stop working. If you administer this PC remotely "
                "with PsExec or WMI, note that Strict blocks that and Balanced does not."
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Enforces everything, including the rules that block unfamiliar software.",
            detail=(
                "Everything in Balanced, with the two audited rules now enforcing, plus a block on "
                "process creation from PsExec and WMI. Cloud block level goes to High Plus and the "
                "cloud is given longer to reach a verdict before a file is allowed to run.\n\n"
                "The significant change is the prevalence rule: a program that is not common, not old, "
                "and not on a trusted list does not run. That is genuinely effective against malware "
                "built specifically for you, which by definition no signature exists for."
            ),
            breaks=(
                "Expect real friction, and expect it from software you trust. Anything freshly "
                "compiled, niche, in beta, or written by you is blocked for being unusual until its "
                "reputation builds — which can take days. Packed or minified scripts shipped by "
                "legitimate commercial software can trip the obfuscation rule. Remote administration "
                "of this PC via PsExec or WMI stops.\n\n"
                "Choose this if you would rather an unfamiliar program be refused than trusted, and be "
                "ready to add an exclusion or step back to Balanced when something you need is caught."
            ),
        ),
    ),
)


# -- Exploit & Ransomware -----------------------------------------------------

EXPLOIT = Family(
    id="exploit",
    title="Exploit protection & ransomware",
    subtitle="System-wide memory protections, protected folders, and disk encryption.",
    footnote=(
        "Exploit protection settings apply to each program the next time it starts. Restart "
        "anything important, or reboot when convenient, to be sure it picked them up.\n\n"
        "BitLocker is never switched on by this app without its recovery key already saved. "
        "Without that key a firmware update or a failed boot can make every file on the drive "
        "permanently unreadable, and no hardening setting is worth that risk."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "System-wide exploit mitigations stay as Windows configured them, Controlled Folder "
                "Access is off, and BitLocker is left exactly as it is — this app never switches "
                "encryption off.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing changes. Documents, photos and backups remain writable by any program that "
                "runs as you, which is precisely what ransomware relies on."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Turn on the memory protections. Nothing you use will notice.",
            detail=(
                "Enables the system-wide exploit mitigations that make memory-corruption bugs much "
                "harder to turn into working exploits: Data Execution Prevention, bottom-up and "
                "high-entropy address space randomisation, SEHOP, and Control Flow Guard.\n\n"
                "These are the mature, well-tested mitigations. Most modern software is already built "
                "expecting them."
            ),
            breaks=(
                "In practice nothing. Very old 32-bit software occasionally objects to SEHOP or DEP; "
                "if something that worked yesterday stops starting, this is the level to step back "
                "from."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Adds Controlled Folder Access — ransomware cannot touch your documents.",
            detail=(
                "Everything in Basic, plus Controlled Folder Access in Audit mode first and then "
                "enforcing: only programs Defender recognises as trustworthy may write to Documents, "
                "Pictures, Videos, Music, Desktop and Favourites. Ransomware that gets onto the "
                "machine finds it cannot encrypt the files that matter.\n\n"
                "Also reports BitLocker's status and whether a recovery key has been saved. It does "
                "not enable encryption at this level."
            ),
            breaks=(
                "This is the level that generates real interruptions, and they look alarming when "
                "they happen. A program you use and trust — a text editor, a game saving to Documents, "
                "a backup tool, a photo editor — can be blocked from writing, usually silently. "
                "Windows Security shows the block and offers to allow that application; once allowed "
                "it stays allowed.\n\n"
                "Expect to add two or three exceptions in the first week and none after that."
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Mandatory ASLR, and BitLocker must be on with its recovery key saved.",
            detail=(
                "Everything in Balanced, plus mandatory address space randomisation for programs that "
                "did not opt into it themselves, and a stricter Controlled Folder Access posture.\n\n"
                "This level also requires full disk encryption. It will not apply until BitLocker is "
                "on and its recovery key has been saved somewhere you can actually reach — your "
                "Microsoft account, a printout, or a file on a different drive. If no key is saved, "
                "the level is refused with an explanation rather than applied."
            ),
            breaks=(
                "Mandatory ASLR is the one setting here that breaks real, current software. Programs "
                "not built to be relocated — some older games, a few Java and Electron applications, "
                "various hardware utilities — will fail to start, usually with no useful error. "
                "There is no way to predict which; you find out by trying.\n\n"
                "Enable this if you are willing to add per-application exceptions when something "
                "refuses to launch, and to recognise a mysterious startup failure as this setting."
            ),
        ),
    ),
)


# -- Network exposure ---------------------------------------------------------

EXPOSURE = Family(
    id="exposure",
    title="Network exposure",
    subtitle="Legacy protocols, remote access, and the services that answer strangers.",
    footnote=(
        "Everything here reduces what this PC will talk to or answer on a network. None of it "
        "affects your ability to reach out to the internet.\n\n"
        "Remote Desktop is never switched off while you are connected over Remote Desktop — that "
        "would end the session and leave no way back without physical access to the machine."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "SMBv1 stays as installed, LLMNR and NetBIOS keep broadcasting, AutoRun stays "
                "enabled, and whichever remote-access services are on stay on.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing changes. On any shared network — an office, a hotel, a café — this PC keeps "
                "announcing its own name over LLMNR and NetBIOS and trusting whatever answers, which "
                "is the standard way a laptop is tricked into handing over a password hash."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Remove SMBv1 and disable AutoRun. Both are obsolete; neither is missed.",
            detail=(
                "Removes the SMBv1 protocol entirely. It is thirty years old, was the vehicle for "
                "WannaCry and NotPetya, and Microsoft has been removing it from Windows by default for "
                "years. Also disables AutoRun and AutoPlay for every drive type, closing the "
                "plug-in-a-USB-stick-and-it-runs route.\n\n"
                "Turns off the Remote Registry service, which lets other machines read this one's "
                "registry and has no place on a desktop."
            ),
            breaks=(
                "Realistically nothing. SMBv1 is only needed to reach network shares on Windows XP or "
                "Server 2003 machines, or a handful of very old NAS boxes and network scanners. If you "
                "have such a device, you will find its shares unreachable — the fix is to update the "
                "device, which needs doing anyway."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Silence LLMNR, NetBIOS, mDNS and WPAD. Turn off Remote Desktop.",
            detail=(
                "Everything in Basic, plus the name-resolution protocols that make this PC shout its "
                "queries onto the local network and believe whatever replies: LLMNR, NetBIOS over "
                "TCP/IP, mDNS, and WPAD proxy auto-discovery. Every one of them is a standard tool in "
                "any attacker's kit for collecting credentials on a shared network.\n\n"
                "Requires SMB signing so a share connection cannot be silently relayed, and switches "
                "off Remote Desktop and WinRM — neither of which a personal desktop normally accepts."
            ),
            breaks=(
                "Reaching other machines by bare hostname stops working, so \\\\my-desktop needs the "
                "full name or the IP address instead. Some network printers and older NAS devices are "
                "discovered over these protocols and will need adding by IP.\n\n"
                "Remote Desktop into this PC stops working. If you rely on it, turn that one toggle "
                "back on afterwards — the rest of the level still applies. If you are reading this "
                "over Remote Desktop, this level will be refused rather than cut you off."
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Close the remaining inbound surface. This PC stops answering the network.",
            detail=(
                "Everything in Balanced, plus the firewall's default inbound action set to Block on "
                "all three profiles, network discovery and file and printer sharing switched off "
                "everywhere, and the remaining remote-management services disabled.\n\n"
                "After this the machine makes outbound connections normally and answers essentially "
                "nothing unsolicited."
            ),
            breaks=(
                "Sharing files or printers from this PC stops entirely, and it disappears from other "
                "machines' network views. Anything that expects an inbound connection — game hosting, "
                "media serving, a local development server another device connects to, casting to a "
                "TV — stops working until you add a specific firewall rule for it.\n\n"
                "This is the right setting for a laptop that only ever consumes network services, and "
                "the wrong one for a PC other devices in the house depend on."
            ),
        ),
    ),
)


# -- Credential theft ---------------------------------------------------------

CREDENTIAL = Family(
    id="credential",
    title="Credential protection",
    subtitle="How hard it is to steal the passwords and tokens held on this PC.",
    footnote=(
        "LSA Protection and Credential Guard both take effect only after a reboot, and both can "
        "prevent third-party software that hooks into Windows authentication from loading — "
        "smartcard middleware, some VPN clients, certain password managers and older biometric "
        "drivers.\n\n"
        "Microsoft notes that with LSA Protection enabled, the Defender ASR rule that blocks "
        "credential theft from lsass.exe becomes redundant. Both are offered because a machine "
        "that cannot run one can usually run the other."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "User Account Control stays at its shipped setting, the Guest account stays as it is, "
                "and lsass.exe runs unprotected.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing changes. Anything running with Administrator rights on this PC can read "
                "credentials straight out of memory — the technique behind essentially every "
                "one-machine-becomes-the-whole-network story."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Tighten UAC, disable the Guest account, and stop caching plaintext passwords.",
            detail=(
                "Sets User Account Control to always prompt on the secure desktop, so an elevation "
                "prompt cannot be faked or clicked through by another program, and applies UAC to the "
                "built-in Administrator account too. Disables the Guest account and anonymous "
                "enumeration of accounts and shares.\n\n"
                "Switches off WDigest credential caching, which stores your password in memory in a "
                "form that can be read back as plain text. It exists only for compatibility with "
                "authentication nobody has used in fifteen years."
            ),
            breaks=(
                "Nothing, beyond seeing the UAC prompt slightly more often than before. Windows has "
                "not needed WDigest since Server 2003, and nothing on a modern desktop uses it."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Turn on LSA Protection so the credential store cannot be read.",
            detail=(
                "Everything in Basic, plus LSA Protection: lsass.exe is started as a protected "
                "process, which means even a program running as Administrator cannot read its memory. "
                "This is what stops Mimikatz and everything shaped like it.\n\n"
                "Restricts remote access to the SAM database and hardens NTLM handling. Takes effect "
                "after a reboot."
            ),
            breaks=(
                "Software that legitimately hooks into Windows authentication stops loading, because "
                "it is no longer allowed into the protected process. That means some smartcard "
                "middleware, a few enterprise VPN clients, certain fingerprint readers, and password "
                "managers that integrate with Windows sign-in.\n\n"
                "If sign-in behaves oddly after the reboot, this is the setting to step back from. "
                "Windows logs what was refused in the Event Log under LSASS."
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Adds Credential Guard. Strong protection, real hardware consequences.",
            detail=(
                "Everything in Balanced, plus virtualisation-based Credential Guard: secrets are moved "
                "into a separate virtualised environment the main operating system cannot reach at "
                "all, even when it is fully compromised. Hypervisor-enforced code integrity is enabled "
                "alongside it.\n\n"
                "Needs UEFI, Secure Boot, and hardware virtualisation. Requires a reboot."
            ),
            breaks=(
                "The most invasive setting in this app. Credential Guard takes the hypervisor for "
                "itself, so other virtualisation may stop working — VMware Workstation and VirtualBox "
                "historically conflict, Android emulators frequently break, and nested virtualisation "
                "becomes unreliable. Older device drivers that fail hypervisor-enforced code integrity "
                "will not load, which on a laptop can mean a peripheral simply stops working after the "
                "reboot.\n\n"
                "It also cannot be turned off casually: reverting requires a reboot and, on some "
                "machines, clearing a UEFI variable. Read the reboot note above before choosing this, "
                "and do not choose it on a machine you cannot afford to troubleshoot."
            ),
        ),
    ),
)


# -- DNS privacy --------------------------------------------------------------

DNS = Family(
    id="dns",
    title="DNS privacy",
    subtitle="Whether the names you look up are encrypted, and who answers them.",
    footnote=(
        "An honest difference from Linux worth stating plainly: Windows has no client-side DNSSEC "
        "validation equivalent to systemd-resolved's. Strict here means DNS-over-HTTPS is "
        "mandatory with no fallback to unencrypted DNS — the transport is encrypted and the server "
        "authenticated — but the answers themselves are not signature-checked. This app does not "
        "claim otherwise.\n\n"
        "Pinning a resolver is a separate choice from the level, and while a VPN is up the right "
        "answer is usually Automatic: the tunnel resolves names at the far end, and pinning a "
        "public resolver would send your lookups around the tunnel instead of through it."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "Lookups leave this PC the way Windows ships them: in plain text, over UDP port 53, "
                "to whichever server your router, ISP or VPN handed out.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing breaks, because nothing changes — but anyone sharing your network, anyone "
                "running it, and your ISP can all read every domain you visit, and can forge answers "
                "to send you somewhere else."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Encrypt lookups where the resolver supports it. Nothing breaks.",
            detail=(
                "Turns on DNS-over-HTTPS with automatic upgrade and fallback still permitted. Windows "
                "encrypts lookups to any resolver it knows speaks DoH, and quietly uses plain DNS when "
                "it does not.\n\n"
                "Strictly better than Off on networks that support encryption, and identical to Off on "
                "the ones that do not."
            ),
            breaks=(
                "Nothing. Because fallback is still allowed, captive portals, hotel WiFi and corporate "
                "networks all keep working exactly as before."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Encrypted lookups, and stop announcing yourself on the local network.",
            detail=(
                "Everything in Basic, plus LLMNR, mDNS and NetBIOS name resolution switched off. Those "
                "are the protocols that make this PC broadcast the name it is looking for and accept "
                "whatever machine answers first — the well-worn route to collecting credentials on a "
                "shared network.\n\n"
                "This is the right setting for a laptop that leaves the house."
            ),
            breaks=(
                "Reaching other machines by bare hostname stops working; use the full name or IP. Some "
                "printers and cast-to-TV devices are found over mDNS and may need adding manually.\n\n"
                "(These are the same protocols the Network Exposure family disables at its Balanced "
                "level. Applying both is harmless — they set the same values.)"
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Encrypted or not at all. Will break some networks.",
            detail=(
                "Everything in Balanced, with fallback removed: DNS-over-HTTPS becomes mandatory. A "
                "lookup that cannot be encrypted is refused rather than downgraded, so nothing on the "
                "network can watch or tamper with which sites you visit.\n\n"
                "This level needs a pinned resolver that speaks DoH. Choose one below before applying "
                "it, or name resolution will stop on any network whose own resolver does not."
            ),
            breaks=(
                "Quite a lot, on the wrong network. Captive portals — hotels, airports, cafés, trains "
                "— cannot be logged into, because the portal works by intercepting exactly the DNS "
                "this level refuses to send unencrypted. Corporate networks with internal-only "
                "hostnames stop resolving them.\n\n"
                "Pair this with a pinned resolver, and expect to step down to Balanced when you "
                "travel."
            ),
        ),
    ),
)


# -- TLS & crypto -------------------------------------------------------------

TLS = Family(
    id="tls",
    title="TLS & cryptography",
    subtitle="The floor for how weak a connection this PC will accept.",
    footnote=(
        "These settings change SCHANNEL, the component every Windows program uses for TLS, so they "
        "apply system-wide — browsers, Windows Update, Office, .NET applications and anything else "
        "using the OS for encryption. Chrome and Firefox partly use their own TLS stacks and are "
        "less affected.\n\n"
        "Each program picks the new floor up the next time it starts. Reboot when convenient to be "
        "sure everything has."
    ),
    levels=(
        Level(
            id="off",
            label="Off",
            summary="Windows defaults. No changes.",
            detail=(
                "SCHANNEL stays as Windows configured it, which on Windows 11 already disables SSL 2.0 "
                "and 3.0 but leaves TLS 1.0 and 1.1 available for compatibility.\n\n" + _OFF_BOILERPLATE
            ),
            breaks=(
                "Nothing changes. Connections can still negotiate down to TLS 1.0 and to cipher suites "
                "using 3DES and RC4, which are broken rather than merely dated."
            ),
        ),
        Level(
            id="basic",
            label="Basic",
            summary="Turn off SSL 2.0/3.0 and the genuinely broken ciphers.",
            detail=(
                "Explicitly disables SSL 2.0 and SSL 3.0 for both client and server, and switches off "
                "RC4 in all its sizes along with DES and NULL ciphers. Enables TLS 1.2 explicitly "
                "rather than leaving it to the default, and turns on strong cryptography for .NET "
                "applications, which otherwise pick their own weaker defaults."
            ),
            breaks=(
                "In practice nothing. Everything switched off here has been considered broken for a "
                "decade, and no current website or service depends on it."
            ),
        ),
        Level(
            id="balanced",
            label="Balanced",
            summary="Require TLS 1.2 or better, and drop 3DES. The daily driver.",
            detail=(
                "Everything in Basic, plus TLS 1.0 and TLS 1.1 disabled for both client and server, "
                "3DES removed, and TLS 1.3 enabled where the machine supports it. The cipher suite "
                "order is set to prefer forward-secret AES-GCM and ChaCha20 suites.\n\n"
                "TLS 1.2 has been the practical minimum for years; every major browser and site "
                "requires it already."
            ),
            breaks=(
                "Mostly local devices rather than websites. Printer and NAS web interfaces, older "
                "routers, IP cameras, embedded management consoles and building equipment frequently "
                "cannot do better than TLS 1.0 and will stop loading. A handful of neglected corporate "
                "and government sites are in the same position.\n\n"
                "Connections fail cleanly rather than silently downgrading, so you will know."
            ),
        ),
        Level(
            id="strict",
            label="Strict",
            summary="Modern cryptography only. Expect breakage you do not control.",
            detail=(
                "Everything in Balanced, plus CBC-mode cipher suites removed in favour of AEAD only, "
                "a raised minimum for Diffie-Hellman and RSA key sizes, and weak signature and hash "
                "algorithms disabled across the board.\n\n"
                "This is a commitment, not a tweak. It applies to every program on the system that "
                "uses Windows for TLS."
            ),
            breaks=(
                "Expect real breakage, in places you cannot fix. Older HTTPS sites, corporate VPN "
                "concentrators, mail servers, embedded devices, printer interfaces and anything not "
                "updated in several years will fail to connect. Some Windows components that talk to "
                "older infrastructure may too.\n\n"
                "Choose this if you would rather a connection fail than fall back to weak "
                "cryptography, and be ready to step down to Balanced when something you need refuses "
                "to work."
            ),
        ),
    ),
)


FAMILIES = (DEFENDER, EXPLOIT, EXPOSURE, CREDENTIAL, DNS, TLS)
BY_ID = {family.id: family for family in FAMILIES}

LEVEL_IDS = ("off", "basic", "balanced", "strict")


def get_family(family_id):
    return BY_ID.get(family_id)
