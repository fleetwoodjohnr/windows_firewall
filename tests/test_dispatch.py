"""End-to-end through the privileged decision path -- validate, guard, act,
journal -- with every component stubbed. This is the broker minus its pipe."""

import os

import pytest

from broker.dispatch import ActionError, Context, Dispatcher
from broker.guards import StubProbes
from broker.protocol import (
    ERR_BLOCKED,
    ERR_FAILED,
    ERR_PROTOCOL,
    ERR_VALIDATION,
    decode_response,
)
from broker.registry_txn import FakeRegistry, StateStore

HIVE, PATH = "HKLM", r"SOFTWARE\Test"


class SpyFamily:
    """Records what it was asked to do, and writes one journalled value."""

    def __init__(self, fail_on=None, blocked=False):
        self.applied = []
        self.reverted = 0
        self._fail_on = fail_on
        self._blocked = blocked

    def apply(self, txn, level, ctx):
        if self._blocked:
            raise ActionError("Windows said no", ERR_BLOCKED)
        if level == self._fail_on:
            txn.set_reg(HIVE, PATH, "Half", "REG_DWORD", 1)
            raise RuntimeError("blew up half way")
        self.applied.append(level)
        txn.set_reg(HIVE, PATH, "Value", "REG_DWORD", {"basic": 1, "balanced": 2, "strict": 3}[level])
        return {"note": level}

    def revert(self, txn, ctx):
        self.reverted += 1
        return {"serviceRestarted": True}

    def status(self, ctx):
        return {"live": "read"}


@pytest.fixture
def env(tmp_path):
    registry = FakeRegistry()
    store = StateStore(os.path.join(tmp_path, "state.json"))
    family = SpyFamily()
    context = Context(store, registry, StubProbes(), {"dns": family})
    return Dispatcher(context), registry, store, family


def call(dispatcher, **kw):
    frame = dispatcher.handle_frame({"protocol": 1, "id": "r1", **kw})
    _rid, ok, result, kind, message = decode_response(frame)
    return ok, result, kind, message


class TestHappyPath:
    def test_ping(self, env):
        dispatcher, *_ = env
        ok, result, _k, _m = call(dispatcher, verb="ping")
        assert ok and result["alive"] is True

    def test_apply_then_revert(self, env):
        dispatcher, registry, store, family = env
        ok, result, _k, _m = call(dispatcher, verb="apply", family="dns", level="balanced")
        assert ok and result["level"] == "balanced" and result["note"] == "balanced"
        assert registry.read_value(HIVE, PATH, "Value") == (True, "REG_DWORD", 2)
        assert store.level("dns") == "balanced"

        ok, result, _k, _m = call(dispatcher, verb="revert", family="dns")
        assert ok and result["level"] == "off"
        assert registry.read_value(HIVE, PATH, "Value") == (False, None, None)
        assert family.reverted == 1

    def test_apply_off_is_routed_to_revert(self, env):
        dispatcher, registry, store, family = env
        call(dispatcher, verb="apply", family="dns", level="strict")
        ok, result, _k, _m = call(dispatcher, verb="apply", family="dns", level="off")
        assert ok and result["level"] == "off"
        assert family.reverted == 1
        assert registry.read_value(HIVE, PATH, "Value")[0] is False

    def test_status_separates_recorded_from_live(self, env):
        dispatcher, *_ = env
        call(dispatcher, verb="apply", family="dns", level="basic")
        ok, result, _k, _m = call(dispatcher, verb="status")
        assert ok
        # Never merged: a disagreement between them means somebody changed a
        # setting outside this app, and that is real information.
        assert result["recorded"]["families"]["dns"]["level"] == "basic"
        assert result["live"]["dns"] == {"live": "read"}

    def test_status_survives_one_unreadable_family(self, tmp_path):
        class Broken:
            def status(self, ctx):
                raise RuntimeError("WMI is wedged")

        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(), StubProbes(),
            {"dns": SpyFamily(), "tls": Broken()}))
        ok, result, _k, _m = call(dispatcher, verb="status")
        assert ok
        assert result["live"]["dns"] == {"live": "read"}
        assert "error" in result["live"]["tls"]


class TestRejection:
    def test_rejects_an_unknown_verb(self, env):
        dispatcher, *_ = env
        ok, _r, kind, _m = call(dispatcher, verb="format-c")
        assert not ok and kind == ERR_VALIDATION

    def test_rejects_a_bad_level(self, env):
        dispatcher, *_ = env
        ok, _r, kind, _m = call(dispatcher, verb="apply", family="dns", level="ultra")
        assert not ok and kind == ERR_VALIDATION

    def test_rejects_a_protocol_mismatch(self, env):
        dispatcher, *_ = env
        _rid, ok, _r, kind, _m = decode_response(
            dispatcher.handle_frame({"protocol": 2, "id": "r1", "verb": "ping"}))
        assert not ok and kind == ERR_PROTOCOL

    def test_answers_even_an_unparseable_request(self, env):
        """A client left waiting for a reply that never comes is a control
        greyed out forever."""
        dispatcher, *_ = env
        _rid, ok, _r, _kind, _m = decode_response(dispatcher.handle_frame({"garbage": True}))
        assert ok is False

    def test_rejects_an_unregistered_family(self, tmp_path):
        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(), StubProbes(), {}))
        ok, _r, kind, _m = call(dispatcher, verb="apply", family="tls", level="basic")
        assert not ok and kind == ERR_VALIDATION


class TestGuardIntegration:
    def test_a_guard_refusal_stops_the_action(self, tmp_path):
        family = SpyFamily()
        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(),
            StubProbes(tamper=True), {"defender": family}))
        ok, _r, kind, message = call(dispatcher, verb="apply", family="defender", level="basic")
        assert not ok and kind == ERR_BLOCKED
        assert "Tamper Protection" in message
        assert family.applied == [], "the action must not run after a refusal"

    def test_a_guard_never_blocks_a_read(self, tmp_path):
        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(),
            StubProbes(tamper=True, remote=True), {"defender": SpyFamily()}))
        assert call(dispatcher, verb="status")[0] is True


class TestFailure:
    def test_an_action_error_is_reported_with_its_kind(self, tmp_path):
        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(), StubProbes(),
            {"dns": SpyFamily(blocked=True)}))
        ok, _r, kind, message = call(dispatcher, verb="apply", family="dns", level="basic")
        assert not ok and kind == ERR_BLOCKED and message == "Windows said no"

    def test_an_unexpected_crash_still_answers(self, tmp_path):
        dispatcher = Dispatcher(Context(
            StateStore(os.path.join(tmp_path, "s.json")), FakeRegistry(), StubProbes(),
            {"dns": SpyFamily(fail_on="strict")}))
        ok, _r, kind, _m = call(dispatcher, verb="apply", family="dns", level="strict")
        assert not ok and kind == ERR_FAILED

    def test_a_half_applied_level_is_still_revertable(self, tmp_path):
        """The property that matters most: a crash part-way through leaves
        everything it touched journalled, so revert still cleans up."""
        registry = FakeRegistry()
        store = StateStore(os.path.join(tmp_path, "s.json"))
        dispatcher = Dispatcher(Context(
            store, registry, StubProbes(), {"dns": SpyFamily(fail_on="strict")}))

        call(dispatcher, verb="apply", family="dns", level="strict")
        assert registry.read_value(HIVE, PATH, "Half")[0] is True
        assert store.level("dns") == "off", "a failed apply must not record itself as applied"

        ok, _r, _k, _m = call(dispatcher, verb="revert", family="dns")
        assert ok
        assert registry.read_value(HIVE, PATH, "Half") == (False, None, None)

    def test_a_failed_restore_is_reported_not_swallowed(self, tmp_path):
        class Locked(FakeRegistry):
            def delete_value(self, *a, **k):
                raise OSError("locked by policy")

        registry = Locked()
        store = StateStore(os.path.join(tmp_path, "s.json"))
        dispatcher = Dispatcher(Context(store, registry, StubProbes(), {"dns": SpyFamily()}))
        call(dispatcher, verb="apply", family="dns", level="basic")
        ok, result, _k, _m = call(dispatcher, verb="revert", family="dns")
        assert ok
        assert result["restoreFailures"], "a failed restore must be surfaced"
        assert result["level"] != "off"


class TestShutdown:
    def test_shutdown_sets_the_exit_flag(self, env):
        dispatcher, *_ = env
        assert dispatcher.should_exit is False
        ok, result, _k, _m = call(dispatcher, verb="shutdown")
        assert ok and result["stopping"] is True
        assert dispatcher.should_exit is True
