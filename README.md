# Windows Firewall & Hardening

A desktop app for seeing and changing what protects a Windows 11 PC: what the
firewall lets in, whether Microsoft Defender's behavioural rules are actually
enforcing, how hard it is to steal the credentials in memory, whether DNS
lookups leave in plain text, and how weak a connection the machine will accept.

Ported from [a GTK4 app for Fedora](https://github.com/fleetwoodjohnr/fedora_firewall_gui)
that did the same job for `firewalld`. None of that plumbing survives — every
backend here is Windows — but the design does, and the design is the point.

## What makes it different from a hardening script

**Every level tells you what it will break, before you apply it.** Choosing
"Strict" from a dropdown teaches you nothing. Each of the six level selectors
shows what a level turns on and what it costs, and asks for confirmation with
that text in front of you. Where the honest answer is "expect real breakage in
places you don't control", that is what it says.

**Every change is undoable, exactly.** Before writing anything, the original is
recorded. Reverting restores it — and where a value did not previously exist,
reverting *deletes* it rather than writing a guessed default, because absent and
default-valued are different states. Uninstalling reverts everything first, so
the app never leaves settings behind that outlive the thing that explained them.

**Controls show the system, never your request.** A switch moves only after the
change actually lands. That matters more on Windows than on Linux: Tamper
Protection, group policy and licence tiers can all accept a change and discard
it, and a control that moved on click would report protection the machine does
not have.

**It refuses things that would lock you out.** It will not disable Remote
Desktop from inside a Remote Desktop session. It will not apply a level
requiring BitLocker until the recovery key is saved somewhere. It will not
pretend a Defender level applied while Tamper Protection was silently discarding
it. Each refusal explains what to do instead.

## Install

Download `WinHardenSetup.exe` from a release and run it. It is self-contained —
Python and Qt are bundled, and nothing is fetched at install time.

To build it yourself on a Windows 11 machine:

```powershell
git clone <this repo>
cd windows-firewall
.\scripts\bootstrap.ps1
```

That installs Python and Inno Setup via `winget`, installs the Python
dependencies, runs the test suite, and builds `installer\Output\WinHardenSetup-1.0.0.exe`.
Everything the build needs is downloaded there, once, so the installer it
produces needs nothing.

## Pages

- **Dashboard** — what is protecting this PC right now, panic mode, and specific
  findings each with the one action that fixes it. If something could not be
  read, it says so rather than showing a clean result it never verified.
- **Firewall Rules** — the inbound rule groups open on each of Windows' three
  profiles, with a plain-English risk note. A partly-enabled group is shown as
  partly enabled, not rounded to on or off.
- **Networks** — public or private per connected adapter, and which resolver
  answers its lookups.
- **Protection** — Defender and ASR, exploit protection and ransomware, plus all
  18 desktop ASR rules individually.
- **Hardening** — network exposure, credential protection, DNS privacy, TLS.

## The six levels

Each is Off / Basic / Balanced / Strict. Basic is meant to be free — if a level
called Basic breaks something you use, that is a bug in this app.

| | Basic | Balanced | Strict |
|---|---|---|---|
| **Defender & ASR** | cloud protection, PUA blocking, 8 document/email rules | + credential, ransomware, driver and USB rules | + enforces the rules that block unfamiliar software |
| **Exploit & ransomware** | DEP, ASLR, SEHOP, CFG | + Controlled Folder Access | + mandatory ASLR, BitLocker required |
| **Network exposure** | SMBv1 removed, AutoRun off | + LLMNR/NetBIOS/mDNS/WPAD off, RDP off | + default-deny inbound |
| **Credential protection** | UAC tightened, WDigest off | + LSA Protection | + Credential Guard |
| **DNS privacy** | DoH where available | + local name protocols off | + DoH mandatory, no fallback |
| **TLS & crypto** | SSL 2/3 and RC4 off | + TLS 1.0/1.1 and 3DES off | + AEAD only, weak hashes off |

## How privilege works

Windows has no polkit — no way to authorise one action and go back to being
unprivileged. So the GUI runs unelevated and never elevates. The first
privileged change starts a small broker through UAC, which stays alive for the
session and listens on a named pipe.

```
win-harden.exe (asInvoker)
      |  ShellExecuteEx "runas"  ->  one UAC prompt per session
      v
win-harden-broker.exe (requireAdministrator)
      ^
      |  \\.\pipe\win-harden-<SID>   DACL: that SID, SYSTEM, Administrators
      |  accepts: a verb, and values from fixed lists. Nothing else.
```

Reads never go near it, so opening a page never prompts.

The broker accepts a verb and values matched against fixed lists — no paths, no
addresses, no free text. Its own tables decide what a level means; it takes a
level *id* from the GUI and looks the meaning up itself. Everything it runs is
`powershell.exe -NoProfile -File <one of 15 shipped scripts>` with parameters
bound as data. Never `-Command`: an argv list is not enough when one element can
be a script. Each script re-validates its own parameters with `[ValidateSet]`,
so the check happens twice, in two languages, in two processes — and a test
asserts the two agree.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install PySide6 pytest
.venv/bin/python -m pytest tests -q
```

The suite runs on Linux and macOS as well as Windows. Everything except the
Windows API calls themselves is covered: the trust boundary, the revert
mechanism, all six families round-tripping against a fake registry, the
cross-language script validation, and the UI — including the guarantee that a
refused change never moves its control.

What cannot be tested off Windows, and must be checked on the real machine:
the UAC prompt and pipe handshake, whether each PowerShell script does what it
claims, and that a reboot after Credential Guard or LSA Protection still boots.
