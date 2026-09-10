"""Restore records survive interruption, corruption, and level downgrades."""
import json
import pytest
from broker.registry_txn import FakeRegistry, RegistryError, StateStore, Transaction


def test_original_is_durable_before_registry_mutation(tmp_path):
    path = tmp_path / 'state.json'
    class CheckedRegistry(FakeRegistry):
        def write_value(self, hive, key, name, kind, value):
            snapshot = StateStore(path).snapshot()
            assert len(snapshot['originals']) == 1
            assert snapshot['families']['one']['claims']
            super().write_value(hive, key, name, kind, value)
    registry = CheckedRegistry()
    store = StateStore(path)
    txn = Transaction(store, 'one', registry=registry)
    txn.begin('strict')
    txn.set_reg('HKLM', 'Software\\Test', 'new', 'REG_DWORD', 1)
    # Simulate exit before commit: the next process can still undo this write.
    assert StateStore(path).family("one")["incomplete"]
    resumed = Transaction(StateStore(path), 'one', registry=registry)
    assert not resumed.revert()
    assert not StateStore(path).family("one").get("incomplete")
    assert registry.read_value('HKLM', 'Software\\Test', 'new') == (False, None, None)


def test_downgrade_restores_settings_no_longer_used(tmp_path):
    registry = FakeRegistry()
    store = StateStore(tmp_path / 'state.json')
    strict = Transaction(store, 'one', registry=registry)
    strict.begin('strict')
    strict.set_reg('HKLM', 'Software\\Test', 'basic', 'REG_DWORD', 1)
    strict.set_reg('HKLM', 'Software\\Test', 'strict', 'REG_DWORD', 2)
    strict.commit('strict')
    basic = Transaction(store, 'one', registry=registry)
    basic.begin('basic')
    basic.set_reg('HKLM', 'Software\\Test', 'basic', 'REG_DWORD', 1)
    basic.commit('basic')
    assert registry.read_value('HKLM', 'Software\\Test', 'strict') == (False, None, None)
    assert registry.read_value('HKLM', 'Software\\Test', 'basic') == (True, 'REG_DWORD', 1)


def test_partially_applied_family_still_holds_shared_original(tmp_path):
    store = StateStore(tmp_path / 'state.json')
    registry = FakeRegistry()
    one = Transaction(store, 'one', registry=registry)
    one.begin('basic')
    one.set_reg('HKLM', 'Software\\Test', 'shared', 'REG_DWORD', 1)
    # First family failed before commit. Its claim must not be lost.
    two = Transaction(store, 'two', registry=registry)
    two.begin('basic')
    two.set_reg('HKLM', 'Software\\Test', 'shared', 'REG_DWORD', 1)
    two.commit('basic')
    assert not two.revert()
    assert registry.read_value('HKLM', 'Software\\Test', 'shared')[0]
    assert not one.revert()
    assert not registry.read_value('HKLM', 'Software\\Test', 'shared')[0]


@pytest.mark.parametrize('data', [[], {'version':999}, {'families': []}, {'originals': []},
    {'families': {'one': 'broken'}}, {'families': {'one': {'claims':[3]}}}, {'originals':{'a':None}}])
def test_invalid_journal_is_retained_and_refused(tmp_path, data):
    path = tmp_path / 'state.json'
    original = json.dumps(data)
    path.write_text(original)
    with pytest.raises(RegistryError):
        StateStore(path)
    assert path.read_text() == original
