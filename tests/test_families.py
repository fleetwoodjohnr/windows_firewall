"""Every level family, applied and reverted end-to-end.

The property under test is the one the whole design exists to provide:

    After walking a family up to any level and back to Off, the machine is
    byte-for-byte where it started -- values that existed are restored to their
    old contents, and values the app created are gone rather than set to a
    guessed default.

Run against a fake registry and a fake PowerShell runner, so it exercises the
real action modules and the real journal on any platform.
"""

import copy
import os

import pytest

from broker import asr_catalog, guards
from broker.actions import load_families
from broker.dispatch import Context, Dispatcher
from broker.protocol import FAMILIES, decode_response
from broker.psinvoke import build_argv
from broker.registry_txn import FakeRegistry, StateStore

# A machine with some pre-existing values, so restoration has something real to
# put back rather than only deletions to perform.
PRE_EXISTING = {
    FakeRegistry.key("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                     "ConsentPromptBehaviorAdmin"): ("REG_DWORD", 5),
    FakeRegistry.key("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa",
                     "LmCompatibilityLevel"): ("REG_DWORD", 3),
    FakeRegistry.key("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
                     "Enabled"): ("REG_DWORD", 1),
    FakeRegistry.key("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "NoDriveTypeAutoRun"): ("REG_DWORD", 145),
}


class FakeRunner:
    """Stands in for powershell.exe. Records every invocation, and answers the
    status scripts with a plausible payload.

    Crucially it validates each call through the real `build_argv`, so a family
    that tried to pass an unvalidated value would fail here rather than in
    production.
    """

    def __init__(self):
        self.calls = []
        self.state = {
            "preferences": {
                "mapsReporting": "Disabled",
                "submitSamples": "AlwaysPrompt",
                "cloudBlockLevel": "Default",
                "puaProtection": "Disabled",
                "networkProtection": "Disabled",
                "controlledFolderAccess": "Disabled",
                "cloudExtendedTimeout": "0",
            },
            "mitigations": {"dep": True, "sehop": False, "cfg": False,
                            "aslr-bottomup": False, "aslr-highentropy": False,
                            "aslr-force": False},
        }

    def __call__(self, script, params=None):
        build_argv(script, params, script_root="/ps")  # the real validator
        self.calls.append((script, dict(params or {})))

        if script == "status-defender.ps1":
            return {
                "isTamperProtected": False,
                "realtimeProtection": True,
                "signatureAgeDays": 0,
                "preferences": dict(self.state["preferences"]),
                "asrRules": [{"id": r.guid, "action": 0} for r in asr_catalog.RULES],
            }
        if script == "status-hardening.ps1":
            return {
                "mitigations": dict(self.state["mitigations"]),
                "bitlocker": [{"mountPoint": "C:", "protectionOn": True, "recoveryKeySaved": True}],
            }
        if script == "status-services.ps1":
            return {
                "services": [
                    {"name": "RemoteRegistry", "startType": "Manual", "running": False},
                    {"name": "WinRM", "startType": "Manual", "running": False},
                    {"name": "TermService", "startType": "Automatic", "running": True},
                ],
                "features": [{"name": "SMB1Protocol", "enabled": True}],
                "sshAuthorizedKeyPresent": True,
            }
        if script == "status-network.ps1":
            return {"interfaces": [{"index": 12, "name": "Wi-Fi", "category": "Public"}]}
        return {}

    def scripts_called(self):
        return [script for script, _params in self.calls]


def make(tmp_path, probes=None):
    registry = FakeRegistry(copy.deepcopy(PRE_EXISTING))
    store = StateStore(os.path.join(tmp_path, "state.json"))
    runner = FakeRunner()
    context = Context(store, registry, probes or guards.StubProbes(),
                      load_families(), runner=runner)
    return Dispatcher(context), registry, store, runner


def call(dispatcher, **kw):
    _rid, ok, result, kind, message = decode_response(
        dispatcher.handle_frame({"protocol": 1, "id": "r", **kw}))
    return ok, result, kind, message


@pytest.mark.parametrize("family", FAMILIES)
class TestEveryFamily:
    def test_applies_each_level(self, tmp_path, family):
        dispatcher, _registry, store, _runner = make(tmp_path)
        for level in ("basic", "balanced", "strict"):
            ok, _result, _kind, message = call(
                dispatcher, verb="apply", family=family, level=level)
            assert ok, f"{family}/{level} failed: {message}"
            assert store.level(family) == level

    def test_round_trip_restores_the_machine_exactly(self, tmp_path, family):
        dispatcher, registry, store, _runner = make(tmp_path)
        before = copy.deepcopy(registry.values)

        ok, _r, _k, message = call(dispatcher, verb="apply", family=family, level="strict")
        assert ok, message
        ok, _r, _k, message = call(dispatcher, verb="apply", family=family, level="off")
        assert ok, message

        assert registry.values == before, (
            f"{family} did not restore the registry exactly.\n"
            f"added:   {set(registry.values) - set(before)}\n"
            f"removed: {set(before) - set(registry.values)}\n"
            f"changed: {{k for k in before if k in registry.values "
            f"and before[k] != registry.values[k]}}"
        )
        assert store.level(family) == "off"

    def test_walking_up_then_off_restores_the_true_original(self, tmp_path, family):
        """Basic -> Balanced -> Strict -> Off must restore the machine's real
        original, not whatever Basic happened to write."""
        dispatcher, registry, store, _runner = make(tmp_path)
        before = copy.deepcopy(registry.values)

        for level in ("basic", "balanced", "strict", "off"):
            ok, _r, _k, message = call(dispatcher, verb="apply", family=family, level=level)
            assert ok, f"{family}/{level}: {message}"

        assert registry.values == before

    def test_status_is_readable_at_every_level(self, tmp_path, family):
        dispatcher, *_ = make(tmp_path)
        for level in ("basic", "strict", "off"):
            call(dispatcher, verb="apply", family=family, level=level)
            ok, result, _k, _m = call(dispatcher, verb="status")
            assert ok
            assert "error" not in (result["live"][family] or {}), result["live"][family]


class TestFamiliesTogether:
    def test_all_six_applied_then_all_reverted(self, tmp_path):
        """The realistic case: someone hardens everything, then undoes it."""
        dispatcher, registry, store, _runner = make(tmp_path)
        before = copy.deepcopy(registry.values)

        for family in FAMILIES:
            ok, _r, _k, message = call(dispatcher, verb="apply", family=family, level="strict")
            assert ok, f"{family}: {message}"

        for family in FAMILIES:
            ok, _r, _k, message = call(dispatcher, verb="revert", family=family)
            assert ok, f"{family}: {message}"

        assert registry.values == before
        assert all(level == "off" for level in store.all_levels().values())

    def test_overlapping_families_do_not_corrupt_each_others_originals(self, tmp_path):
        """dns and exposure both write EnableMulticast and EnableMDNS. Whichever
        journals first holds the true original, and reverting both must still
        end at the original value rather than at the other family's."""
        dispatcher, registry, store, _runner = make(tmp_path)
        registry.write_value("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                             "EnableMulticast", "REG_DWORD", 1)
        before = copy.deepcopy(registry.values)

        call(dispatcher, verb="apply", family="dns", level="balanced")
        call(dispatcher, verb="apply", family="exposure", level="balanced")
        call(dispatcher, verb="revert", family="exposure")
        call(dispatcher, verb="revert", family="dns")

        assert registry.values == before


class TestDefenderSpecifics:
    def test_cloud_protection_is_enabled_before_cloud_dependent_rules(self, tmp_path):
        dispatcher, _registry, _store, runner = make(tmp_path)
        call(dispatcher, verb="apply", family="defender", level="balanced")

        maps_index = next(
            i for i, (script, params) in enumerate(runner.calls)
            if script == "set-defender.ps1" and params.get("Setting") == "mapsReporting")
        cloud_rules = {r.guid for r in asr_catalog.RULES if r.needs_cloud}
        rule_indexes = [
            i for i, (script, params) in enumerate(runner.calls)
            if script == "set-asr.ps1" and params.get("RuleId") in cloud_rules]
        assert rule_indexes, "no cloud-dependent rules were applied at balanced"
        assert maps_index < min(rule_indexes), (
            "cloud-dependent ASR rules were enabled before cloud protection was on, "
            "which leaves them configured and inert")

    def test_warn_is_never_sent_to_a_rule_that_lacks_it(self, tmp_path):
        dispatcher, _registry, _store, runner = make(tmp_path)
        for level in ("basic", "balanced", "strict"):
            call(dispatcher, verb="apply", family="defender", level=level)
        no_warn = {r.guid for r in asr_catalog.RULES if not r.supports_warn}
        for script, params in runner.calls:
            if script == "set-asr.ps1" and params["RuleId"] in no_warn:
                assert params["Action"] != "warn", f"{params['RuleId']} has no Warn mode"

    def test_the_exchange_only_rule_is_never_applied(self, tmp_path):
        dispatcher, _registry, _store, runner = make(tmp_path)
        call(dispatcher, verb="apply", family="defender", level="strict")
        server_only = {r.guid for r in asr_catalog.RULES if not r.desktop_relevant}
        applied = {p["RuleId"] for s, p in runner.calls if s == "set-asr.ps1"}
        assert not (applied & server_only)

    def test_setting_a_warn_only_rule_to_warn_is_refused_with_an_explanation(self, tmp_path):
        dispatcher, *_ = make(tmp_path)
        rule = next(r for r in asr_catalog.RULES if not r.supports_warn)
        ok, _r, _kind, message = call(
            dispatcher, verb="set-asr", asr_rule=rule.guid, asr_action="warn")
        assert not ok
        assert "Warn" in message and "Audit" in message

    def test_reverting_restores_prior_asr_actions(self, tmp_path):
        dispatcher, _registry, _store, runner = make(tmp_path)
        call(dispatcher, verb="apply", family="defender", level="strict")
        runner.calls.clear()
        call(dispatcher, verb="revert", family="defender")

        restored = [p for s, p in runner.calls if s == "set-asr.ps1"]
        assert restored, "revert did not restore any ASR rule"
        # Every rule was off beforehand in the fake, so every restore is to off.
        assert all(p["Action"] == "off" for p in restored)


class TestPowerShellDiscipline:
    def test_every_call_a_family_makes_passes_the_real_validator(self, tmp_path):
        """FakeRunner routes each call through build_argv, so this passing means
        no family constructed an invocation the allowlist would reject."""
        dispatcher, _registry, _store, runner = make(tmp_path)
        for family in FAMILIES:
            for level in ("basic", "balanced", "strict", "off"):
                call(dispatcher, verb="apply", family=family, level=level)
        assert runner.calls, "no PowerShell calls were made at all"

    def test_no_family_ever_names_a_script_outside_the_allowlist(self, tmp_path):
        dispatcher, _registry, _store, runner = make(tmp_path)
        for family in FAMILIES:
            call(dispatcher, verb="apply", family=family, level="strict")
        from broker.psinvoke import SCRIPTS
        for script in runner.scripts_called():
            assert script in SCRIPTS
