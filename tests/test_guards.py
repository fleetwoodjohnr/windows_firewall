"""The changes this app refuses to make. Each of these protects against a way to
lock yourself out of your own computer."""

import pytest

from broker import guards
from broker.protocol import ERR_BLOCKED, ERR_GUARD, validate_request


def req(**kw):
    return validate_request({"protocol": 1, "id": "r", **kw})


class TestRdpLockout:
    def test_refuses_to_disable_rdp_from_an_rdp_session(self):
        refusal = guards.check(
            req(verb="set-toggle", toggle="rdp", enabled=False),
            guards.StubProbes(remote=True))
        assert refusal is not None and refusal.kind == ERR_GUARD

    def test_allows_disabling_rdp_at_the_console(self):
        assert guards.check(
            req(verb="set-toggle", toggle="rdp", enabled=False),
            guards.StubProbes(remote=False)) is None

    def test_allows_enabling_rdp_from_anywhere(self):
        assert guards.check(
            req(verb="set-toggle", toggle="rdp", enabled=True),
            guards.StubProbes(remote=True)) is None

    @pytest.mark.parametrize("level", guards.RDP_DISABLED_FROM)
    def test_refuses_an_exposure_level_that_would_disable_rdp(self, level):
        refusal = guards.check(
            req(verb="apply", family="exposure", level=level),
            guards.StubProbes(remote=True))
        assert refusal is not None and refusal.kind == ERR_GUARD

    def test_allows_a_lower_exposure_level_that_leaves_rdp_alone(self):
        assert guards.check(
            req(verb="apply", family="exposure", level="basic"),
            guards.StubProbes(remote=True)) is None


class TestTamperProtection:
    @pytest.mark.parametrize("family", guards.DEFENDER_BACKED_FAMILIES)
    @pytest.mark.parametrize("level", ["basic", "balanced", "strict"])
    def test_refuses_a_defender_level_while_tampered(self, family, level):
        refusal = guards.check(
            req(verb="apply", family=family, level=level),
            guards.StubProbes(tamper=True))
        # blocked, not failed: Windows refused, the app did nothing wrong.
        assert refusal is not None and refusal.kind == ERR_BLOCKED

    @pytest.mark.parametrize("family", guards.DEFENDER_BACKED_FAMILIES)
    def test_revert_is_never_blocked(self, family):
        """You must always be able to undo, even on a machine where you can no
        longer apply."""
        assert guards.check(
            req(verb="apply", family=family, level="off"),
            guards.StubProbes(tamper=True)) is None
        assert guards.check(
            req(verb="revert", family=family),
            guards.StubProbes(tamper=True)) is None

    def test_refuses_enabling_an_asr_rule_while_tampered(self):
        refusal = guards.check(
            req(verb="set-asr", asr_rule="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
                asr_action="block"),
            guards.StubProbes(tamper=True))
        assert refusal is not None and refusal.kind == ERR_BLOCKED

    def test_allows_turning_an_asr_rule_off_while_tampered(self):
        assert guards.check(
            req(verb="set-asr", asr_rule="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
                asr_action="off"),
            guards.StubProbes(tamper=True)) is None

    def test_families_not_backed_by_defender_are_unaffected(self):
        for family in ("dns", "tls", "credential", "exposure"):
            assert guards.check(
                req(verb="apply", family=family, level="basic"),
                guards.StubProbes(tamper=True)) is None


class TestBitlocker:
    def test_refuses_strict_without_a_saved_recovery_key(self):
        refusal = guards.check(
            req(verb="apply", family="exploit", level="strict"),
            guards.StubProbes(bitlocker_key=False))
        assert refusal is not None and refusal.kind == ERR_GUARD
        assert "recovery key" in refusal.message

    def test_allows_strict_once_the_key_is_saved(self):
        assert guards.check(
            req(verb="apply", family="exploit", level="strict"),
            guards.StubProbes(bitlocker_key=True)) is None

    def test_lower_levels_do_not_require_a_key(self):
        for level in ("basic", "balanced"):
            assert guards.check(
                req(verb="apply", family="exploit", level=level),
                guards.StubProbes(bitlocker_key=False)) is None


class TestMessages:
    def test_every_refusal_explains_what_to_do_instead(self):
        for message in (guards.RDP_LOCKOUT, guards.BITLOCKER_NO_KEY, guards.TAMPER_PROTECTED):
            assert len(message) > 120, "a refusal must explain itself, not just refuse"
            assert "\n\n" in message, "refusals are written as prose, not a single line"


class TestUnguardedPaths:
    def test_a_plain_read_is_never_guarded(self):
        for verb in ("status", "ping"):
            assert guards.check(req(verb=verb), guards.StubProbes(
                remote=True, tamper=True, bitlocker_key=False, ssh_key=False)) is None
