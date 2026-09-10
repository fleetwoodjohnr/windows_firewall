"""How this app is allowed to call PowerShell.

Shared, like `protocol.py` and `registry_txn.py`: the broker runs these commands
elevated via `subprocess`, the GUI runs the read-only ones unelevated via
`subprocess.Popen`, and both build their argv here so there is exactly one
definition of what may be executed.

The Fedora helper's rule was "No shell, anywhere. subprocess is always called
with an argv list." An argv list is necessary on Windows too, but on its own it
is not sufficient, because PowerShell will happily take code as an argument:

    powershell.exe -Command "Set-MpPreference -Foo $userInput"   # NO

That is a shell, spelled differently. Passing an argv list does not help when
one element of the list is a script. So the rule here is stronger:

  * Only ever `-File <path>`, never `-Command`. The script is a real file on
    disk that shipped with the installer.
  * The path must be one of `SCRIPTS` below. A caller cannot name a file.
  * Parameters are separate argv elements, `-Name` then value, so PowerShell
    binds them as data. They are never formatted into script text.
  * Every value is checked against the pattern its parameter declares, and no
    value may begin with `-` (which PowerShell would read as the next parameter
    name rather than as this one's value).
  * Each `.ps1` re-declares its own `[ValidateSet(...)]` on the same parameter.
    The check is deliberately made twice, in two languages, by two processes.

`-NoProfile` matters as much as the rest: without it PowerShell executes the
machine's profile scripts first, which is arbitrary code we did not audit
running inside an elevated process.
"""

import os
import re

# Fixed prelude for every invocation.
#   -NoProfile        don't run profile scripts inside an elevated process
#   -NonInteractive   never block waiting for input nobody can see
#   -ExecutionPolicy Bypass   these are our own shipped files, and a machine
#                     policy of AllSigned must not silently disable hardening
#   -OutputFormat Text        we parse our own JSON, not CLIXML
BASE_FLAGS = (
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-OutputFormat", "Text",
)

from scanner.paths import system_powershell
POWERSHELL = system_powershell()

# Parameter value patterns. A parameter whose name is not here cannot be passed.
PARAM_PATTERNS = {
    'Reset': r'^(yes|no)$',
    'Resource': r'^(firewall|netbios|guest|dns)$',
    'Data': r'^[A-Za-z0-9+/=]{1,65536}$',
    'ServiceName': r'^(RemoteRegistry|WinRM|TermService|sshd)$',
    'StartupType': r'^(Automatic|Manual|Disabled|AutomaticDelayedStart)$',
    "Level": r"^(off|basic|balanced|strict)$",
    "Provider": r"^(automatic|quad9|cloudflare|mullvad|adguard)$",
    "Profile": r"^(Domain|Private|Public|All)$",
    "Action": r"^(off|audit|warn|block)$",
    "State": r"^(on|off)$",
    "Category": r"^(Public|Private)$",
    # Filled in below from TOGGLE_IDS, so a typo'd toggle is refused here rather
    # than reaching a .ps1 that silently has no branch for it.
    "Toggle": None,
    "RuleId": r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$",
    "InterfaceIndex": r"^[0-9]{1,10}$",
    # Defender preference name and value. Both are closed enums so that
    # restoring a prior value goes through exactly the same validation as
    # setting a new one -- a journal must never become a way to pass free text
    # into an elevated process.
    "Setting": r"^(mapsReporting|submitSamples|cloudBlockLevel|puaProtection"
               r"|controlledFolderAccess|networkProtection|cloudExtendedTimeout"
               r"|realtimeMonitoring|ioavProtection)$",
    "Value": r"^(Disabled|Basic|Advanced|AlwaysPrompt|SendSafeSamples|NeverSend"
             r"|SendAllSamples|Default|Moderate|High|HighPlus|ZeroTolerance"
             r"|Enabled|AuditMode|BlockDiskModificationOnly|AuditDiskModificationOnly|True|False|0|10|20|30|40|50)$",
    "Mitigation": r"^(dep|aslr-bottomup|aslr-highentropy|aslr-force|sehop|cfg)$",
    # A firewall rule group's display name is the one parameter carrying text we
    # did not author -- Windows supplies it and the GUI hands it back. It is
    # still never interpolated into script text: it crosses as one argv element
    # into a -File script, and the pattern below excludes quotes, $, ;, | and
    # backtick so that a group name cannot resemble PowerShell syntax even if
    # some future caller did the wrong thing with it.
    "Group": r"^[\w ()/.,+&_'-]{1,128}$",
}

# Every switchable component, as one authoritative list.
#
# `protocol.TOGGLES` is the subset the GUI is allowed to ask for. The rest are
# used by the broker's own level modules -- a level switches NetBIOS off, but
# there is no button for it, because it belongs to a level rather than standing
# on its own. Keeping both in one place means a level cannot reference a toggle
# that no script implements, and a test asserts the GUI's list is a subset.
TOGGLE_IDS = (
    # GUI-facing
    "openssh-server",
    "smb1",
    "rdp",
    "winrm",
    "remote-registry",
    "firewall-domain",
    "firewall-private",
    "firewall-public",
    "panic-mode",
    # broker-internal, driven by level modules
    "netbios",
    "inbound-block",
    "guest-account",
    "wpad-service",
)

PARAM_PATTERNS["Toggle"] = "^(" + "|".join(TOGGLE_IDS) + ")$"

# script file name -> the parameters it accepts. Required params are listed in
# `required`; anything in `optional` may be omitted.
SCRIPTS = {
    'status-system.ps1': {'required': ('Resource',), 'optional': ()},
    'restore-system.ps1': {'required': ('Resource', 'Data'), 'optional': ()},
    'set-service.ps1': {'required': ('ServiceName', 'StartupType', 'State'), 'optional': ()},
    # -- reads: run unelevated by the GUI, never prompt ------------------------
    "status-firewall.ps1": {"required": (), "optional": ()},
    "status-network.ps1": {"required": (), "optional": ()},
    "status-defender.ps1": {"required": (), "optional": ()},
    "status-services.ps1": {"required": (), "optional": ()},
    "status-hardening.ps1": {"required": (), "optional": ()},
    "list-rule-groups.ps1": {"required": ("Profile",), "optional": ()},
    # -- writes: broker only, elevated ----------------------------------------
    "set-firewall-profile.ps1": {"required": ("Profile", "State"), "optional": ()},
    "set-rule-group.ps1": {"required": ("Profile", "Group", "State"), "optional": ()},
    "set-panic.ps1": {"required": ("State",), "optional": ()},
    "set-network-category.ps1": {"required": ("InterfaceIndex", "Category"), "optional": ()},
    "set-dns-provider.ps1": {"required": ("InterfaceIndex", "Provider"), "optional": ()},
    "set-asr.ps1": {"required": ("RuleId", "Action"), "optional": ('Reset',)},
    "set-toggle.ps1": {"required": ("Toggle", "State"), "optional": ()},
    "set-defender.ps1": {"required": ("Setting", "Value"), "optional": ()},
    "set-mitigation.ps1": {"required": ("Mitigation", "State"), "optional": ('Reset',)},
}

# Reads are the subset the GUI may run in its own unelevated process.
READ_SCRIPTS = tuple(name for name in SCRIPTS if name.startswith(("status-", "list-")))


class InvocationError(Exception):
    """A PowerShell invocation this module refused to construct."""


def script_dir():
    """Where the shipped .ps1 files live, relative to this file.

    Resolved from __file__ rather than a working directory or an environment
    variable: an elevated process must not take the location of the code it runs
    from anything a lower-privileged caller could influence.
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "scripts", "ps")


def build_argv(script, params=None, script_root=None):
    """Return the full argv for one PowerShell invocation.

    Raises InvocationError rather than building anything questionable.
    """
    if script not in SCRIPTS:
        raise InvocationError(f"{script!r} is not one of this app's scripts")

    spec = SCRIPTS[script]
    params = dict(params or {})

    permitted = set(spec["required"]) | set(spec["optional"])
    for name in params:
        if name not in permitted:
            raise InvocationError(f"{script} does not accept parameter {name!r}")
    for name in spec["required"]:
        if name not in params:
            raise InvocationError(f"{script} requires parameter {name!r}")

    root = script_root if script_root is not None else script_dir()
    path = os.path.normpath(os.path.join(root, script))
    # Belt and braces: even though `script` came from SCRIPTS, confirm the joined
    # path did not escape the script directory.
    if os.path.basename(path) != script:
        raise InvocationError(f"refusing a script path that does not end in {script!r}")

    argv = [POWERSHELL, *BASE_FLAGS, "-File", path]
    for name in spec["required"] + spec["optional"]:
        if name not in params:
            continue
        argv.extend(["-" + name, _checked_value(name, params[name])])
    return argv


def _checked_value(name, value):
    pattern = PARAM_PATTERNS.get(name)
    if pattern is None:
        raise InvocationError(f"parameter {name!r} has no declared value pattern")
    if isinstance(value, bool):
        raise InvocationError(f"parameter {name!r} was given a bool; pass an explicit string")
    text = str(value)
    # PowerShell reads a leading '-' as the start of the next parameter name, so
    # a value shaped like a switch would silently rebind rather than be passed.
    if text.startswith("-"):
        raise InvocationError(f"{name}={text!r} may not begin with '-'")
    if not re.match(pattern, text):
        raise InvocationError(f"{name}={text!r} does not match {pattern}")
    return text


def is_read_only(script):
    return script in READ_SCRIPTS
