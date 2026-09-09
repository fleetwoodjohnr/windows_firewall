"""Microsoft Defender and Attack Surface Reduction: the authoritative settings.

Defender's state does not live in the registry in any form this app should write
directly -- `Set-MpPreference` is the supported interface, and poking the
underlying keys is how you get a machine whose Defender UI and actual behaviour
disagree. So this family journals differently from the registry-based ones: it
records the *prior value* of each preference it changes and restores it through
the same setter.

That has a consequence worth being explicit about. A journal entry cannot carry
a blob of prior settings to be splatted back, because handing free-form data to
an elevated process is exactly what the trust boundary forbids. Instead each
preference is a closed enum on both sides -- `Setting` and `Value` in
`psinvoke.PARAM_PATTERNS` -- so restoring a prior value goes through precisely
the same validation as setting a new one.

Tamper Protection is checked by `guards.check` before any of this runs. If it is
on, the level is refused rather than applied, because `Set-MpPreference` would
silently discard most of it and the app would then report protection that does
not exist.
"""

from .. import asr_catalog
from ..registry_txn import register_restorer

# Preference -> the value each level wants. Cumulative: a level inherits
# everything below it and overrides what it names again.
_LEVEL_PREFERENCES = {
    "basic": {
        # Advanced membership: an unknown file is judged against what Microsoft
        # is seeing globally, not only against yesterday's signatures. Three ASR
        # rules do nothing at all without this.
        "mapsReporting": "Advanced",
        "submitSamples": "SendSafeSamples",
        # Blocks bundled adware, fake optimisers and browser hijackers, which
        # ordinary antivirus deliberately ignores because they are not viruses.
        "puaProtection": "Enabled",
        "networkProtection": "Enabled",
    },
    "balanced": {
        "cloudBlockLevel": "High",
        "cloudExtendedTimeout": "50",
    },
    "strict": {
        "cloudBlockLevel": "HighPlus",
    },
}

_ORDER = ("basic", "balanced", "strict")


def preferences_for(level):
    """Everything up to and including `level`, later levels overriding."""
    merged = {}
    for name in _ORDER:
        merged.update(_LEVEL_PREFERENCES.get(name, {}))
        if name == level:
            break
    return merged


# -- journal restorers --------------------------------------------------------

def _restore_preference(entry, context):
    runner = context.get("runner")
    if runner is None:
        return
    value = entry.get("value")
    if value is None:
        # We could not read the prior value, so we do not guess one. Leaving it
        # is honest; writing a default would be inventing state the machine
        # never had.
        return
    runner("set-defender.ps1", {"Setting": entry["setting"], "Value": str(value)})


def _restore_asr(entry, context):
    runner = context.get("runner")
    if runner is None:
        return
    runner("set-asr.ps1", {"RuleId": entry["guid"], "Action": entry.get("action") or "off"})


register_restorer("mppref", _restore_preference)
register_restorer("asr", _restore_asr)


# -- reading current state ----------------------------------------------------

def _current(ctx):
    if ctx.runner is None:
        return {}
    try:
        return ctx.runner("status-defender.ps1") or {}
    except Exception:  # noqa: BLE001 - an unreadable probe must not stop a revert
        return {}


def _current_asr_actions(status):
    """guid (lowercase) -> action id, from what Defender reports right now."""
    actions = {}
    for entry in status.get("asrRules") or []:
        guid = str(entry.get("id", "")).lower().strip("{}")
        action = entry.get("action")
        if isinstance(action, int):
            action = asr_catalog.MP_TO_ACTION.get(action)
        if guid:
            actions[guid] = action or "off"
    return actions


# -- apply / revert -----------------------------------------------------------

def apply(txn, level, ctx):
    if ctx.runner is None:
        raise RuntimeError("no PowerShell runner is available")

    status = _current(ctx)
    prior_prefs = status.get("preferences") or {}
    prior_asr = _current_asr_actions(status)

    # Preferences first. Cloud protection has to be on before the three
    # cloud-dependent ASR rules are enabled, or they are configured and inert.
    wanted = preferences_for(level)
    for setting, value in wanted.items():
        txn.record("mppref", f"mppref:{setting}", {
            "setting": setting,
            "value": prior_prefs.get(setting),
        })
        ctx.runner("set-defender.ps1", {"Setting": setting, "Value": value})

    # Then the rules.
    applied_rules = {}
    for rule in asr_catalog.desktop_rules():
        action = asr_catalog.action_for(rule.guid, level)
        if action is None:
            continue
        if action == "warn" and not rule.supports_warn:
            # Two rules genuinely have no Warn mode. Asking for it would be
            # accepted and quietly treated as something else.
            action = "block"
        txn.record("asr", f"asr:{rule.guid}", {
            "guid": rule.guid,
            "action": prior_asr.get(rule.guid, "off"),
        })
        ctx.runner("set-asr.ps1", {"RuleId": rule.guid, "Action": action})
        applied_rules[rule.guid] = action

    return {
        "preferences": wanted,
        "rules": applied_rules,
        "notes": {
            "rulesEnforced": sum(1 for a in applied_rules.values() if a == "block"),
            "rulesAudited": sum(1 for a in applied_rules.values() if a == "audit"),
        },
    }
    if live.get("error"):
        out["error"] = live["error"]
    return out


def revert(txn, ctx):
    # Everything is journalled, so the replay does the work. Nothing extra to
    # undo here -- Defender needs no restart and holds no file we wrote.
    return {}


def set_asr_rule(rule_id, action, ctx):
    """One rule, from the Protection page's per-rule list."""
    guid = rule_id.lower().strip("{}")
    rule = asr_catalog.BY_GUID.get(guid)
    if rule is None:
        raise RuntimeError(f"{rule_id} is not an ASR rule this app knows about")
    if action == "warn" and not rule.supports_warn:
        raise RuntimeError(
            f"'{rule.name}' has no Warn mode — Microsoft supports only Off, Audit and Block "
            f"for this rule. Choose one of those instead."
        )
    if ctx.runner is None:
        raise RuntimeError("no PowerShell runner is available")
    ctx.runner("set-asr.ps1", {"RuleId": rule.guid, "Action": action})
    return {"rule": rule.guid, "action": action}


def status(ctx):
    live = _current(ctx)
    # An `error` key is only present when there actually was one: a status
    # payload carrying "error": None reads as a failure to anything checking for
    # the key rather than its value.
    out = {
        "isTamperProtected": live.get("isTamperProtected"),
        "realtimeProtection": live.get("realtimeProtection"),
        "signatureAgeDays": live.get("signatureAgeDays"),
        "lastScan": live.get("lastScan"),
        "preferences": live.get("preferences") or {},
        "asrRules": _current_asr_actions(live),
    }
    if live.get("error"):
        out["error"] = live["error"]
    return out
