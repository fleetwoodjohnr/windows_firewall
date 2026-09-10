"""Read-only aggregate status, executed as the signed-in user."""
from pathlib import Path
from broker.actions import load_families
from broker.dispatch import Context, Dispatcher
from broker.guards import WindowsProbes
from broker.registry_txn import StateStore, WinRegBackend
from broker.psrun import run_script
from scanner.paths import program_data


def read_status():
    cache = {}
    def runner(script, params=None):
        key = (script, tuple(sorted((params or {}).items())))
        if key not in cache:
            cache[key] = run_script(script, params, timeout=45)
        return cache[key]
    store = StateStore(str(Path(program_data()) / 'win-harden' / 'state.json'))
    context = Context(store, WinRegBackend(), WindowsProbes(runner), load_families(), runner)
    result = Dispatcher(context)._verb_status({})
    # The UI needs levels, not original registry contents.
    result['recorded'] = {'families': result['recorded']['families']}
    return result
