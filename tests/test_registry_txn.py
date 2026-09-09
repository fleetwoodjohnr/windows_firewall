"""The revert mechanism. A hardening tool that cannot cleanly undo itself is
worse than no hardening tool, so this is the most important file in the suite."""

import json
import os

import pytest

from broker.registry_txn import FakeRegistry, StateStore, Transaction

HIVE, PATH = "HKLM", r"SOFTWARE\Test"


@pytest.fixture
def store(tmp_path):
    return StateStore(os.path.join(tmp_path, "state.json"))


@pytest.fixture
def registry():
    return FakeRegistry({FakeRegistry.key(HIVE, PATH, "Existing"): ("REG_DWORD", 5)})


def txn(store, registry, family="credential"):
    return Transaction(store, family, registry=registry)


class TestRoundTrip:
    def test_restores_a_value_that_existed(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.commit("basic")
        assert registry.read_value(HIVE, PATH, "Existing") == (True, "REG_DWORD", 1)

        txn(store, registry).revert()
        assert registry.read_value(HIVE, PATH, "Existing") == (True, "REG_DWORD", 5)

    def test_deletes_a_value_that_did_not_exist(self, store, registry):
        """The clause that is easy to get wrong: absent and default-valued are
        different states, and revert must restore absence rather than write a
        guessed default."""
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Fresh", "REG_DWORD", 1)
        t.commit("basic")
        assert registry.read_value(HIVE, PATH, "Fresh")[0] is True

        txn(store, registry).revert()
        assert registry.read_value(HIVE, PATH, "Fresh") == (False, None, None)

    def test_level_returns_to_off(self, store, registry):
        t = txn(store, registry)
        t.begin("strict")
        t.set_reg(HIVE, PATH, "Fresh", "REG_DWORD", 1)
        t.commit("strict")
        assert store.level("credential") == "strict"
        assert txn(store, registry).revert() == []
        assert store.level("credential") == "off"

    def test_revert_of_an_untouched_family_is_a_no_op(self, store, registry):
        assert txn(store, registry).revert() == []
        assert store.level("credential") == "off"


class TestSteppingBetweenLevels:
    def test_original_survives_a_walk_up_the_levels(self, store, registry):
        """Basic -> Balanced -> Strict must never overwrite the machine's real
        original with one of our own earlier values."""
        for level, value in (("basic", 1), ("balanced", 2), ("strict", 3)):
            t = txn(store, registry)
            t.begin(level)
            t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", value)
            t.commit(level)
        assert registry.read_value(HIVE, PATH, "Existing")[2] == 3

        txn(store, registry).revert()
        assert registry.read_value(HIVE, PATH, "Existing") == (True, "REG_DWORD", 5)

    def test_capture_happens_only_on_the_first_transition(self, store, registry):
        first = txn(store, registry)
        assert first.begin("basic") is True
        first.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        first.commit("basic")

        second = txn(store, registry)
        assert second.begin("strict") is False

    def test_originals_record_each_value_once(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 2)
        t.commit("basic")
        assert len(store.originals()) == 1
        assert len(store.family("credential")["claims"]) == 1
        # The first capture is the true original, not the intermediate value.
        assert next(iter(store.originals().values()))["value"] == 5

    def test_going_off_then_on_recaptures(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.commit("basic")
        txn(store, registry).revert()

        # Something outside the app changed it while we were off.
        registry.write_value(HIVE, PATH, "Existing", "REG_DWORD", 42)

        t2 = txn(store, registry)
        assert t2.begin("basic") is True
        t2.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t2.commit("basic")
        txn(store, registry).revert()
        assert registry.read_value(HIVE, PATH, "Existing")[2] == 42


class TestPartialFailure:
    def test_a_crash_part_way_through_leaves_an_undoable_journal(self, store, registry):
        t = txn(store, registry)
        t.begin("strict")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        with pytest.raises(RuntimeError):
            t.set_reg(HIVE, PATH, "Fresh", "REG_DWORD", 1)
            raise RuntimeError("action blew up here")
        # Never committed, so the level is still off -- but what was written is
        # journalled, and revert still puts it back.
        assert store.level("credential") == "off"
        store.save()
        txn(store, registry).revert()
        assert registry.read_value(HIVE, PATH, "Existing") == (True, "REG_DWORD", 5)
        assert registry.read_value(HIVE, PATH, "Fresh") == (False, None, None)

    def test_one_unrestorable_entry_does_not_strand_the_others(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.set_reg(HIVE, PATH, "Fresh", "REG_DWORD", 1)
        t.commit("basic")

        class Exploding(FakeRegistry):
            def write_value(self, hive, path, name, value_type, value):
                if name == "Existing":
                    raise OSError("key is locked by policy")
                super().write_value(hive, path, name, value_type, value)

        exploding = Exploding(registry.values)
        failures = Transaction(store, "credential", registry=exploding).revert()
        assert len(failures) == 1
        # The one that could be restored, was.
        assert exploding.read_value(HIVE, PATH, "Fresh") == (False, None, None)

    def test_failed_entries_stay_journalled_for_a_retry(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.commit("basic")

        class Exploding(FakeRegistry):
            def write_value(self, *a, **k):
                raise OSError("nope")

        Transaction(store, "credential", registry=Exploding(registry.values)).revert()
        # Dropping either the claim or the recorded original would quietly turn
        # a failed restore into a permanent change.
        assert len(store.family("credential")["claims"]) == 1
        assert len(store.originals()) == 1
        assert store.level("credential") != "off"

        assert Transaction(store, "credential", registry=registry).revert() == []
        assert store.level("credential") == "off"


class TestPersistence:
    def test_state_survives_a_reload(self, store, registry, tmp_path):
        t = txn(store, registry)
        t.begin("balanced")
        t.set_reg(HIVE, PATH, "Existing", "REG_DWORD", 1)
        t.commit("balanced")

        reopened = StateStore(store.path)
        assert reopened.level("credential") == "balanced"
        Transaction(reopened, "credential", registry=registry).revert()
        assert registry.read_value(HIVE, PATH, "Existing")[2] == 5

    def test_a_corrupt_state_file_does_not_crash(self, tmp_path):
        path = os.path.join(tmp_path, "state.json")
        with open(path, "w") as f:
            f.write("{ this is not json")
        assert StateStore(path).level("dns") == "off"

    def test_state_file_is_world_readable(self, store, registry):
        """The unprivileged status path reads this, so opening a page never
        needs elevation."""
        txn(store, registry).commit("off")
        assert os.stat(store.path).st_mode & 0o044

    def test_families_are_independent(self, store, registry):
        a = Transaction(store, "dns", registry=registry)
        a.begin("strict")
        a.set_reg(HIVE, PATH, "Fresh", "REG_DWORD", 1)
        a.commit("strict")

        Transaction(store, "tls", registry=registry).revert()
        assert store.level("dns") == "strict"
        assert registry.read_value(HIVE, PATH, "Fresh")[0] is True


class TestSafety:
    def test_rejects_an_unknown_hive(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        with pytest.raises(Exception):
            t.set_reg("HKEY_MADE_UP", PATH, "X", "REG_DWORD", 1)

    def test_rejects_an_unsupported_value_type(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        with pytest.raises(Exception):
            t.set_reg(HIVE, PATH, "X", "REG_INVENTED", 1)

    def test_journal_is_json_serialisable(self, store, registry):
        t = txn(store, registry)
        t.begin("basic")
        t.set_reg(HIVE, PATH, "Multi", "REG_MULTI_SZ", ["a", "b"])
        t.set_reg(HIVE, PATH, "Bin", "REG_BINARY", "deadbeef")
        t.commit("basic")
        json.loads(open(store.path).read())


class TestSharedValues:
    """Two families legitimately set the same value. This is the case that
    quietly produced a wrong result until the originals table was made
    machine-wide rather than per-family."""

    IDENT = (HIVE, PATH, "Shared")

    def _apply(self, store, registry, family, value):
        t = Transaction(store, family, registry=registry)
        t.begin("balanced")
        t.set_reg(*self.IDENT, "REG_DWORD", value)
        t.commit("balanced")

    def test_second_family_does_not_capture_the_first_families_write(self, store, registry):
        registry.write_value(*self.IDENT, "REG_DWORD", 7)
        self._apply(store, registry, "dns", 0)
        self._apply(store, registry, "exposure", 0)
        # One recorded original, and it is the machine's -- not dns's write.
        assert len(store.originals()) == 1
        assert next(iter(store.originals().values()))["value"] == 7

    def test_reverting_one_leaves_the_value_the_other_still_wants(self, store, registry):
        registry.write_value(*self.IDENT, "REG_DWORD", 7)
        self._apply(store, registry, "dns", 0)
        self._apply(store, registry, "exposure", 0)

        Transaction(store, "exposure", registry=registry).revert()
        # dns is still applied and still wants this off.
        assert registry.read_value(*self.IDENT)[2] == 0
        assert store.level("dns") == "balanced"

    def test_reverting_the_last_claimant_restores_the_original(self, store, registry):
        registry.write_value(*self.IDENT, "REG_DWORD", 7)
        self._apply(store, registry, "dns", 0)
        self._apply(store, registry, "exposure", 0)

        Transaction(store, "exposure", registry=registry).revert()
        Transaction(store, "dns", registry=registry).revert()
        assert registry.read_value(*self.IDENT)[2] == 7
        assert store.originals() == {}

    def test_revert_order_does_not_matter(self, store, registry):
        """The bug this guards against made correctness depend on which family
        happened to be reverted first."""
        for first, second in (("dns", "exposure"), ("exposure", "dns")):
            reg = FakeRegistry()
            st = StateStore(store.path + f".{first}")
            self._apply(st, reg, "dns", 0)
            self._apply(st, reg, "exposure", 0)
            Transaction(st, first, registry=reg).revert()
            Transaction(st, second, registry=reg).revert()
            # The value never existed, so it must be gone -- not left at 0.
            assert reg.read_value(*self.IDENT) == (False, None, None), first
