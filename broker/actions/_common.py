"""Shared machinery for the action modules.

A level is mostly a list of registry values, so declaring them as data and
applying them uniformly means no family hand-rolls its own write loop -- and,
more importantly, no family can write something without it going through the
transaction that journals it first.

`Setting` subclasses cover the three kinds of change a level makes: a registry
value, a service's start type, and a Windows optional feature. The latter two
cannot be expressed as a registry entry, so each registers its own restorer with
`registry_txn` and revert stays one uniform replay.
"""

from dataclasses import dataclass

from ..psinvoke import InvocationError
from ..registry_txn import register_restorer

# Windows service start types, as Get-Service/Set-Service names them.
START_TYPES = ("Automatic", "Manual", "Disabled", "Boot", "System")


@dataclass(frozen=True)
class Reg:
    """One registry value a level sets."""

    hive: str
    path: str
    name: str
    type: str
    value: object

    def apply(self, txn, ctx):
        txn.set_reg(self.hive, self.path, self.name, self.type, self.value)

    @property
    def identity(self):
        return f"{self.hive}\\{self.path}\\{self.name}"


@dataclass(frozen=True)
class Service:
    """A Windows service a level switches off (or on)."""

    name: str
    start_type: str
    stop: bool = True

    def apply(self, txn, ctx):
        runner = ctx.runner
        state = "off" if self.start_type == "Disabled" else "on"
        # Record what it was before touching it, so revert restores the actual
        # previous start type rather than assuming Automatic.
        current = _service_state(runner, self.name)
        txn.record("service", f"service:{self.name}", {
            "service": self.name,
            "startType": current.get("startType"),
            "running": current.get("running"),
            "exists": current.get("exists", False),
        })
        if not current.get("exists", False):
            # A service that isn't installed is already in the state we wanted.
            return
        runner('set-service.ps1', {'ServiceName': self.name, 'StartupType': self.start_type, 'State': state})

    @property
    def identity(self):
        return f"service:{self.name}"


@dataclass(frozen=True)
class Feature:
    """A Windows optional feature a level removes."""

    name: str
    enabled: bool = False

    def apply(self, txn, ctx):
        runner = ctx.runner
        current = _feature_state(runner, self.name)
        txn.record("feature", f"feature:{self.name}", {
            "feature": self.name,
            "enabled": current.get("enabled"),
            "exists": current.get("exists", False),
        })
        if not current.get("exists", False):
            return
        runner("set-toggle.ps1", {
            "Toggle": _feature_toggle(self.name),
            "State": "on" if self.enabled else "off",
        })

    @property
    def identity(self):
        return f"feature:{self.name}"


# The protocol's fixed toggle ids, mapped from the service/feature they stand
# for. A level never names a raw service to PowerShell -- it names a toggle id
# from the same fixed list the GUI is allowed to send.
_SERVICE_TOGGLES = {
    "RemoteRegistry": "remote-registry",
    "WinRM": "winrm",
    "TermService": "rdp",
    "sshd": "openssh-server",
}

_FEATURE_TOGGLES = {
    "SMB1Protocol": "smb1",
}


def _service_toggle(name):
    try:
        return _SERVICE_TOGGLES[name]
    except KeyError:
        raise InvocationError(f"no toggle id is defined for service {name!r}") from None


def _feature_toggle(name):
    try:
        return _FEATURE_TOGGLES[name]
    except KeyError:
        raise InvocationError(f"no toggle id is defined for feature {name!r}") from None


def _service_state(runner, name):
    if runner is None:
        raise InvocationError("System state cannot be read without a Windows runner.")
    try:
        payload = runner("status-services.ps1") or {}
    except Exception as exc:
        raise InvocationError(f"Service state is unreadable: {exc}") from exc
    if (payload.get("serviceErrors") or {}).get(name):
        raise InvocationError(payload["serviceErrors"][name])
    for entry in payload.get("services") or []:
        if str(entry.get("name", "")).lower() == name.lower():
            return {
                "exists": True,
                "startType": entry.get("startType"),
                "running": bool(entry.get("running")),
            }
    return {"exists": False}


def _feature_state(runner, name):
    if runner is None:
        raise InvocationError("System state cannot be read without a Windows runner.")
    try:
        payload = runner("status-services.ps1") or {}
    except Exception as exc:
        raise InvocationError(f"Feature state is unreadable: {exc}") from exc
    if (payload.get("featureErrors") or {}).get(name):
        raise InvocationError(payload["featureErrors"][name])
    for entry in payload.get("features") or []:
        if str(entry.get("name", "")).lower() == name.lower():
            return {"exists": True, "enabled": bool(entry.get("enabled"))}
    return {"exists": False}


# -- restorers ----------------------------------------------------------------

def _restore_service(entry, context):
    runner = context.get("runner")
    if runner is None or not entry.get("exists"):
        return
    # A service that was disabled before we touched it stays disabled.
    state = 'on' if entry.get('running') else 'off'
    if entry.get('startType') not in ('Automatic', 'Manual', 'Disabled', 'AutomaticDelayedStart') or entry.get('running') is None:
        raise RuntimeError('The original service state was not fully recorded.')
    runner('set-service.ps1', {'ServiceName': entry['service'], 'StartupType': entry['startType'], 'State': state})


def _restore_feature(entry, context):
    runner = context.get("runner")
    if runner is None or not entry.get("exists"):
        return
    runner("set-toggle.ps1", {
        "Toggle": _feature_toggle(entry["feature"]),
        "State": "on" if entry.get("enabled") else "off",
    })


register_restorer("service", _restore_service)
register_restorer("feature", _restore_feature)


# -- applying a level ---------------------------------------------------------

def cumulative(levels, level):
    """Everything up to and including `level`, in order.

    Levels are declared as what each one *adds*, and applied cumulatively, so a
    setting introduced at Basic cannot be accidentally omitted from Strict by
    someone editing one list.
    """
    order = ("basic", "balanced", "strict")
    # A dict keyed by identity: a higher level re-declaring a setting REPLACES
    # the lower level's value rather than being skipped as a duplicate. That is
    # the point of a level -- Balanced tightening what Basic set must win.
    # Python dicts keep first-insertion order, so the sequence still reads
    # basic-then-balanced-then-strict while the values are the strongest declared.
    settings = {}
    for name in order:
        for setting in levels.get(name, ()):
            settings[setting.identity] = setting
        if name == level:
            break
    return list(settings.values())


def apply_settings(txn, ctx, levels, level):
    """Apply a level's settings in order, journalling each before it is written.

    Deliberately not wrapped in a try/except. If a setting fails, the exception
    propagates to the dispatcher, which reports it -- and everything applied up
    to that point is already journalled, so revert still cleans up. Swallowing
    the error here would leave a level recorded as applied when it is not.
    """
    applied = []
    for setting in cumulative(levels, level):
        setting.apply(txn, ctx)
        applied.append(setting.identity)
    return applied
