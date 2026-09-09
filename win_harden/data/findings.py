"""Actionable findings for the Dashboard.

Port of the Fedora app's `data/hardening_rules.py`. Same shape -- a predicate
over the machine's reported state, and a title and explanation for when it
matches -- retargeted at what actually goes wrong on Windows.

The point of these, and the reason they are separate from the levels, is that a
level is a commitment and a finding is an observation. A finding says "this
specific thing about your machine is wrong and here is the one action that fixes
it", which is a much easier thing to act on than choosing a posture.

Each finding names the family and level that fixes it, so the Dashboard can send
you to the right control rather than describing it.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    detail: str
    severity: str          # "high" | "medium" | "low"
    #: The family whose live status this finding reads. A finding is only ever
    #: evaluated when that section was actually read back from the machine.
    needs: str
    applies_to: Callable    # (status: dict) -> bool
    fix_page: str = ""      # nav page id
    fix_family: str = ""    # level family that addresses it
    fix_level: str = ""


def _live(status, family):
    return ((status.get("live") or {}).get(family)) or {}


def _was_read(status, family):
    """Whether this family's live state actually came back from the machine.

    This is the difference between "the value is absent, so Windows' default
    applies, and that default is the risky one" -- a real finding -- and "we
    could not read anything", which is not evidence of anything.

    Without this distinction a machine the app cannot talk to shows a dashboard
    full of alarming red findings that were never verified, which is worse than
    showing nothing: it trains the user to disbelieve the page.
    """
    section = _live(status, family)
    return bool(section) and "error" not in section


def _recorded_level(status, family):
    families = ((status.get("recorded") or {}).get("families")) or {}
    return (families.get(family) or {}).get("level", "off")


# -- predicates ---------------------------------------------------------------

def _realtime_off(status):
    return _live(status, "defender").get("realtimeProtection") is False


def _no_asr_rules(status):
    return not (_live(status, "defender").get("asrRules") or {}) and \
        _recorded_level(status, "defender") == "off"


def _signatures_stale(status):
    age = _live(status, "defender").get("signatureAgeDays")
    return age is not None and age > 7


def _bitlocker_off(status):
    volumes = _live(status, "exploit").get("bitlocker") or []
    return bool(volumes) and not any(v.get("protectionOn") for v in volumes)


def _bitlocker_without_key(status):
    volumes = _live(status, "exploit").get("bitlocker") or []
    return any(v.get("protectionOn") and not v.get("recoveryKeySaved") for v in volumes)


def _smb1_present(status):
    features = _live(status, "exposure").get("features") or []
    return any(f.get("name", "").lower() == "smb1protocol" and f.get("enabled") for f in features)


def _llmnr_on(status):
    # 0 means disabled; absent means never configured, which is Windows' default of ON.
    return _live(status, "exposure").get("llmnrDisabled") in (None, 1)


def _lsa_unprotected(status):
    return _live(status, "credential").get("lsaProtection") in (None, 0)


def _wdigest_plaintext(status):
    # Absent is the risky case on older installs; 0 is what we want.
    return _live(status, "credential").get("wdigestPlaintext") not in (0,)


def _rdp_open(status):
    return _live(status, "exposure").get("rdpDenied") in (None, 0)


def _dns_plaintext(status):
    interfaces = _live(status, "dns").get("interfaces") or []
    return bool(interfaces) and not any(i.get("dohEnabled") for i in interfaces)


def _tls_old_enabled(status):
    protocols = _live(status, "tls").get("protocols") or {}
    old = protocols.get("TLS 1.0") or {}
    return old.get("client") is True


FINDINGS = [
    Finding(
        id="realtime-off",
        needs="defender",
        title="Real-time protection is switched off",
        detail=(
            "Microsoft Defender is not scanning as files arrive, so nothing is checked until a "
            "scheduled scan runs — by which time anything malicious has already had its chance to "
            "run. This is the single most important thing on this page.\n\n"
            "If another antivirus is installed, Windows switches Defender off on purpose and this "
            "is expected. If not, turn it back on in Windows Security."
        ),
        severity="high",
        applies_to=_realtime_off,
        fix_page="protection",
    ),
    Finding(
        id="bitlocker-no-key",
        needs="exploit",
        title="BitLocker is on, but a drive has no saved recovery key",
        detail=(
            "The drive is encrypted and there is no recovery password protector on it. If the TPM "
            "is reset, the firmware is updated, or the machine fails to boot cleanly, Windows will "
            "ask for a key that does not exist anywhere — and every file on that drive is gone "
            "permanently.\n\n"
            "Fix this before anything else on this page. In Windows: Manage BitLocker → Back up "
            "your recovery key."
        ),
        severity="high",
        applies_to=_bitlocker_without_key,
        fix_page="protection",
    ),
    Finding(
        id="smb1-present",
        needs="exposure",
        title="SMBv1 is still installed",
        detail=(
            "The thirty-year-old file sharing protocol that WannaCry and NotPetya spread through. "
            "Microsoft has been removing it from Windows by default for years. It is only needed "
            "to reach shares on Windows XP-era machines or some very old NAS boxes."
        ),
        severity="high",
        applies_to=_smb1_present,
        fix_page="hardening",
        fix_family="exposure",
        fix_level="basic",
    ),
    Finding(
        id="no-asr",
        needs="defender",
        title="No Attack Surface Reduction rules are configured",
        detail=(
            "ASR blocks the behaviours malware relies on — an Office document launching PowerShell, "
            "a script arriving by email running, a program reading credentials out of lsass — "
            "rather than trying to recognise the malware itself. It works on every edition of "
            "Windows including Home, and it is the highest-value protection available here.\n\n"
            "Basic enforces the eight document and email rules and breaks almost nothing."
        ),
        severity="high",
        applies_to=_no_asr_rules,
        fix_page="protection",
        fix_family="defender",
        fix_level="basic",
    ),
    Finding(
        id="lsa-unprotected",
        needs="credential",
        title="The credential store can be read by any Administrator",
        detail=(
            "lsass.exe holds the credentials of everyone signed in, and it is not running as a "
            "protected process. Any program running with Administrator rights can read your "
            "password and authentication tokens straight out of its memory. This is the technique "
            "behind essentially every one-machine-becomes-the-whole-network compromise."
        ),
        severity="high",
        applies_to=_lsa_unprotected,
        fix_page="hardening",
        fix_family="credential",
        fix_level="balanced",
    ),
    Finding(
        id="wdigest-plaintext",
        needs="credential",
        title="Windows may be caching your password in a readable form",
        detail=(
            "WDigest stores credentials in memory in a form that can be read back as plain text. "
            "It exists only for authentication nothing has used since Server 2003, and it is the "
            "first thing a credential dumper looks for. Switching it off costs nothing."
        ),
        severity="medium",
        applies_to=_wdigest_plaintext,
        fix_page="hardening",
        fix_family="credential",
        fix_level="basic",
    ),
    Finding(
        id="llmnr-on",
        needs="exposure",
        title="This PC announces its lookups to the local network",
        detail=(
            "LLMNR and NetBIOS make this machine broadcast the name it is trying to reach and "
            "trust whichever machine answers first. On any shared network — an office, a hotel, a "
            "café — this is the standard way a laptop is tricked into handing over a password hash."
        ),
        severity="medium",
        applies_to=_llmnr_on,
        fix_page="hardening",
        fix_family="exposure",
        fix_level="balanced",
    ),
    Finding(
        id="rdp-open",
        needs="exposure",
        title="Remote Desktop is accepting connections",
        detail=(
            "This PC will accept desktop logins from the network. If you do not connect to this "
            "machine remotely, this is inbound attack surface with no benefit — Remote Desktop is "
            "one of the most commonly attacked services on the internet."
        ),
        severity="medium",
        applies_to=_rdp_open,
        fix_page="hardening",
        fix_family="exposure",
        fix_level="balanced",
    ),
    Finding(
        id="dns-plaintext",
        needs="dns",
        title="DNS lookups are leaving this PC unencrypted",
        detail=(
            "Every domain you visit is visible to anyone sharing your network, to whoever runs it, "
            "and to your ISP — and any of them can forge an answer to send you somewhere else. "
            "Basic encrypts lookups where the network supports it and breaks nothing."
        ),
        severity="medium",
        applies_to=_dns_plaintext,
        fix_page="hardening",
        fix_family="dns",
        fix_level="basic",
    ),
    Finding(
        id="bitlocker-off",
        needs="exploit",
        title="The drive is not encrypted",
        detail=(
            "Without disk encryption, anyone who gets hold of this machine can read every file on "
            "it by starting it from a USB stick — no password needed. On a laptop this is the "
            "single most likely way your data actually gets taken.\n\n"
            "Turn BitLocker on in Windows, and save the recovery key when it offers. This app "
            "deliberately does not enable it for you: skipping the key-saving step is how people "
            "lose everything."
        ),
        severity="medium",
        applies_to=_bitlocker_off,
        fix_page="protection",
    ),
    Finding(
        id="tls-old",
        needs="tls",
        title="This PC still accepts TLS 1.0",
        detail=(
            "TLS 1.0 dates from 1999 and has known weaknesses. Every current website and service "
            "requires TLS 1.2 or better already, so turning off the old versions rarely affects "
            "anything you use — the exceptions are usually local devices like printer and NAS web "
            "interfaces."
        ),
        severity="low",
        applies_to=_tls_old_enabled,
        fix_page="hardening",
        fix_family="tls",
        fix_level="balanced",
    ),
    Finding(
        id="signatures-stale",
        needs="defender",
        title="Defender's signatures are out of date",
        detail=(
            "Definitions are more than a week old, which usually means Windows Update has not run "
            "successfully for a while. Cloud-delivered protection covers some of the gap, but only "
            "if it is switched on."
        ),
        severity="medium",
        applies_to=_signatures_stale,
        fix_page="protection",
    ),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def applicable(status):
    """Findings that match, most severe first.

    A predicate that raises is treated as not matching: an unreadable corner of
    the status payload must not blank the whole list, and claiming a problem we
    could not actually verify would be worse than staying quiet about it.
    """
    matched = []
    for finding in FINDINGS:
        if not _was_read(status, finding.needs):
            continue
        try:
            if finding.applies_to(status):
                matched.append(finding)
        except Exception:  # noqa: BLE001
            continue
    return sorted(matched, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))


def unreadable_families(status):
    """Which families the dashboard could not judge, so it can say so rather
    than implying everything is fine."""
    return sorted({
        finding.needs for finding in FINDINGS if not _was_read(status, finding.needs)
    })
