"""Verb routing for the broker: request in, response out, no I/O of its own.

Deliberately free of the pipe, of PowerShell, and of Windows. Everything it
needs arrives in a `Context`, so the whole privileged decision path -- validate,
guard, act, journal -- can be exercised on any machine with stub components.
`broker.py` is then only a transport loop around this.

Order of operations, and none of it is negotiable:

  1. Validate against `protocol.py`. A malformed or unknown request never
     reaches a guard, let alone an action.
  2. Run the guards. A refusal returns before anything is written.
  3. Run the action inside a `Transaction`, so whatever it changes is journalled
     before it changes it.

Step 3 is where a partial failure is handled. An action that raises half-way
through leaves the journal holding everything it captured up to that point, and
the family's recorded level unchanged -- so a subsequent revert still undoes the
part that landed. A half-applied level is recoverable; a half-applied level with
no record of what was touched is not.
"""

import traceback

from . import guards
from .protocol import (
    ERR_FAILED,
    ERR_VALIDATION,
    PROTOCOL_VERSION,
    ProtocolError,
    encode_response,
    is_privileged,
    validate_request,
)
from .registry_txn import Transaction


class ActionError(Exception):
    """An action module failed. `kind` lets it say whether Windows refused
    (blocked) or the change was attempted and did not work (failed)."""

    def __init__(self, message, kind=ERR_FAILED):
        super().__init__(message)
        self.kind = kind


class Context:
    """Everything the dispatcher needs, injected.

    `families` maps a family name to an action module exposing:
        apply(txn, level, ctx) -> dict
        revert(txn, ctx)       -> dict
        status(ctx)            -> dict
    """

    def __init__(self, store, registry, probes, families, runner=None, log=None):
        self.store = store
        self.registry = registry
        self.probes = probes
        self.families = dict(families)
        self.runner = runner
        self.log = log or (lambda _message: None)


class Dispatcher:
    def __init__(self, context):
        self.context = context
        self.should_exit = False

    def handle_frame(self, payload):
        """Take a decoded request payload, return an encoded response frame."""
        # The id is echoed so the client can match a reply to its request. Read
        # it defensively before validation, so even a rejected frame gets an
        # answer the client can pair up rather than a silent drop.
        request_id = payload.get("id") if isinstance(payload, dict) else None
        if not isinstance(request_id, str) or not request_id:
            request_id = "unknown"

        try:
            request = validate_request(payload)
        except ProtocolError as e:
            return encode_response(request_id, False, error_kind=e.kind, error_message=str(e))

        try:
            if is_privileged(request['verb']):
                with self.context.store.exclusive():
                    result = self.dispatch(request)
            else:
                result = self.dispatch(request)
        except ActionError as e:
            self.context.log(f"{request['verb']} failed: {e}")
            return encode_response(request_id, False, error_kind=e.kind, error_message=str(e))
        except Exception as e:  # noqa: BLE001 - the broker must answer, never die
            # An unexpected exception inside an elevated process is exactly the
            # thing that must not take the process down silently: the GUI would
            # sit with a control greyed out forever waiting for a reply.
            self.context.log(f"{request['verb']} raised: {traceback.format_exc()}")
            return encode_response(
                request_id, False, error_kind=ERR_FAILED,
                error_message=f"the privileged helper hit an unexpected error: {e}",
            )

        return encode_response(request_id, True, result=result)

    def dispatch(self, request):
        verb = request["verb"]
        refresh = getattr(self.context.probes, 'refresh', None)
        if refresh:
            refresh()

        if is_privileged(verb):
            refusal = guards.check(request, self.context.probes)
            if refusal is not None:
                raise ActionError(refusal.message, refusal.kind)

        handler = getattr(self, "_verb_" + verb.replace("-", "_"))
        return handler(request)

    # -- reads ----------------------------------------------------------------

    def _verb_ping(self, _request):
        return {"protocol": PROTOCOL_VERSION, "alive": True}

    def _verb_antivirus_action(self, request):
        from scanner.client import submit
        action = request['antivirus_action']
        if action == 'protect':
            current = self.context.runner('status-defender.ps1')
            txn = Transaction(self.context.store, 'antivirus', registry=self.context.registry,
                              context={'runner': self.context.runner, 'registry': self.context.registry})
            txn.begin('on')
            for setting in ('realtimeMonitoring', 'ioavProtection'):
                value = current.get('preferences', {}).get(setting)
                if value not in ('True', 'False'):
                    raise ActionError('The original antivirus protection settings could not be read.')
                txn.record('mppref', 'mppref:' + setting, {'setting': setting, 'value': value})
            txn.commit('on')
        return submit(action, owner_sid=getattr(self.context, 'client_sid', None))

    def _verb_status(self, _request):
        """What is applied right now, per family, plus each family's own reading
        of the live system.

        `recorded` is what we believe we applied; `live` is what the machine
        actually reports. They are returned separately and never merged, because
        a disagreement between them is real information -- somebody changed a
        setting outside this app -- and averaging them away would hide it.
        """
        live = {}
        for name, module in self.context.families.items():
            try:
                live[name] = module.status(self.context)
            except Exception as e:  # noqa: BLE001 - one unreadable family must
                # not blank the whole status page
                live[name] = {"error": str(e)}
        return {
            "protocol": PROTOCOL_VERSION,
            "recorded": self.context.store.snapshot(),
            "live": live,
            "tamperProtected": self._safe_probe(self.context.probes.is_tamper_protected),
            "remoteSession": self._safe_probe(self.context.probes.is_remote_session),
        }

    @staticmethod
    def _safe_probe(probe):
        try:
            return probe()
        except Exception:  # noqa: BLE001
            return None

    # -- writes ---------------------------------------------------------------

    def _family(self, name):
        module = self.context.families.get(name)
        if module is None:
            raise ActionError(f"no action module is registered for {name!r}", ERR_VALIDATION)
        return module

    def _verb_apply(self, request):
        family, level = request["family"], request["level"]
        module = self._family(family)

        if level == "off":
            return self._verb_revert(request)

        txn = Transaction(
            self.context.store, family,
            registry=self.context.registry,
            context={"registry": self.context.registry, "runner": self.context.runner},
        )
        captured_originals = txn.begin(level)
        self.context.log(
            f"apply {family}={level} (capturing originals: {captured_originals})"
        )
        result = module.apply(txn, level, self.context)
        txn.commit(level, notes=result.get("notes") if isinstance(result, dict) else None)
        out = {"family": family, "level": level}
        if isinstance(result, dict):
            out.update(result)
        return out

    def _verb_revert(self, request):
        family = request["family"]
        module = self._family(family)

        txn = Transaction(
            self.context.store, family,
            registry=self.context.registry,
            context={"registry": self.context.registry, "runner": self.context.runner},
        )
        # An action module gets a chance to undo things the journal cannot
        # express (restarting a service, refreshing a policy) before the journal
        # itself is replayed.
        extra = module.revert(txn, self.context) or {}
        failures = txn.revert()
        self.context.log(f"revert {family}: {len(failures)} entries could not be restored")

        out = {"family": family, "level": "off"}
        out.update(extra)
        if failures:
            out["level"] = self.context.store.level(family)
            out["restoreFailures"] = [
                {"entry": entry.get("_id", "?"), "error": str(error)}
                for entry, error in failures
            ]
        return out

    def _verb_set_asr(self, request):
        module = self._family("defender")
        setter = getattr(module, "set_asr_rule", None)
        if setter is None:
            raise ActionError("this build cannot set individual ASR rules", ERR_VALIDATION)
        return setter(request["asr_rule"], request["asr_action"], self.context)

    def _verb_set_toggle(self, request):
        toggle, enabled = request["toggle"], request["enabled"]
        module = self.context.families.get("exposure")
        setter = getattr(module, "set_toggle", None) if module else None
        if setter is None:
            raise ActionError("this build cannot set individual toggles", ERR_VALIDATION)
        return setter(toggle, enabled, self.context)

    def _verb_set_rule_group(self, request):
        module = self.context.families.get("exposure")
        setter = getattr(module, "set_rule_group", None) if module else None
        if setter is None:
            raise ActionError("this build cannot change firewall rule groups", ERR_VALIDATION)
        return setter(request["profile"], request["group"], request["enabled"], self.context)

    def _verb_set_network_category(self, request):
        module = self.context.families.get("exposure")
        setter = getattr(module, "set_network_category", None) if module else None
        if setter is None:
            raise ActionError("this build cannot change a network's category", ERR_VALIDATION)
        return setter(request["interface"], request["category"], self.context)

    def _verb_set_dns_provider(self, request):
        module = self._family("dns")
        setter = getattr(module, "set_provider", None)
        if setter is None:
            raise ActionError("this build cannot pin a resolver", ERR_VALIDATION)
        return setter(request["provider"], request["interface"], self.context)

    def _verb_shutdown(self, _request):
        self.should_exit = True
        return {"stopping": True}
