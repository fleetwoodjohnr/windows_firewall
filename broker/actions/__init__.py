"""Authoritative level definitions, one module per family.

These tables -- not the GUI's copies under `win_harden/data/` -- decide what a
level actually does. The GUI's are display mirrors, kept in step by a test
(`tests/test_mirror.py`) rather than by anyone remembering.

That split is inherited from the Fedora helper, where it is spelled out at
`data/encryption_levels.py:14-18`: the privileged side must never take
instructions from an unprivileged caller about what to write into the system. It
accepts a level id, and looks up the meaning itself.

Each module exposes:

    LEVELS   : dict[str, dict]              authoritative settings per level
    apply(txn, level, ctx)  -> dict         write, journalling as it goes
    revert(txn, ctx)        -> dict         undo anything the journal can't express
    status(ctx)             -> dict         read live state, no privileges needed
"""


def load_families():
    """Import and return the action modules that are present in this build.

    Imported lazily and individually so that one family failing to import -- a
    missing dependency, a syntax error in a module being worked on -- degrades to
    that one family being unavailable rather than to a broker that will not
    start at all.
    """
    families = {}
    for name in ("defender", "exploit", "exposure", "credential", "dns", "tls"):
        try:
            module = __import__(f"broker.actions.{name}", fromlist=[name])
        except ImportError:
            continue
        families[name] = module
    return families
