"""Record-and-restore state journal: the mechanism that makes every hardening
change undoable.

The Fedora app got reversibility almost for free. Its privileged helper only
ever created, rewrote or deleted files it owned, so "undo" was "delete the file"
and it was structurally impossible for a bug to damage config that was already
there.

Windows hardening is mostly registry values and service start types, where that
promise has no equivalent. Setting `EnableLUA` to 1 destroys whatever was there
before, and there is no per-application layer to delete. So the promise has to
be bought explicitly instead:

    Before writing anything, record what was there. Revert restores exactly
    that -- and where a value did not previously exist, revert DELETES it
    rather than writing a guessed default.

That last clause is the one that is easy to get wrong and expensive to get
wrong. Most hardening guides tell you to "set it back to 1" to undo. But if the
value was absent, the OS default applied, and writing an explicit 1 is not a
restoration -- it pins a value the machine never had, and the next Windows
release that changes that default now behaves differently on this machine than
on an untouched one. Absent and default-valued are different states and this
module keeps them different.

Two further rules, both carried over from the Fedora helper:

  * Originals are captured only on the first transition away from `off`. Stepping
    Basic -> Balanced -> Strict must never overwrite the real original with one of
    our own earlier values.
  * The state file is world-readable, so the unprivileged status path can report
    what is applied without an elevation prompt.

Nothing here imports `winreg` at module scope, so the whole mechanism -- which
is the part that most needs testing -- is testable on any platform against
`FakeRegistry`.
"""

import json
import os
import tempfile
from contextlib import contextmanager

STATE_VERSION = 1

# Value types we round-trip. Deliberately a closed set: an unrecognised type is
# refused rather than coerced, because a mis-typed restore is a silent
# corruption of the value we promised to put back.
REG_TYPES = ("REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ")

HIVES = ("HKLM", "HKCU", "HKCR", "HKU")


class RegistryError(Exception):
    pass


# -- backends -----------------------------------------------------------------

class RegistryBackend:
    """Read/write/delete a single registry value.

    Three methods, no key enumeration and no key deletion. We never remove a key
    we did not create, because a key can hold values other than ours and there is
    no safe way to know we are the only writer.
    """

    def read_value(self, hive, path, name):
        """Return (existed: bool, type: str | None, value | None)."""
        raise NotImplementedError

    def write_value(self, hive, path, name, value_type, value):
        raise NotImplementedError

    def delete_value(self, hive, path, name):
        """Deleting an already-absent value is success, not an error -- that is
        the state the caller asked for."""
        raise NotImplementedError


class FakeRegistry(RegistryBackend):
    """In-memory backend for tests. Same semantics as the real one, including
    that deleting an absent value succeeds."""

    def __init__(self, initial=None):
        self.values = dict(initial or {})
        self.writes = []

    @staticmethod
    def key(hive, path, name):
        return (hive, path.lower().rstrip("\\"), name.lower())

    def read_value(self, hive, path, name):
        entry = self.values.get(self.key(hive, path, name))
        if entry is None:
            return False, None, None
        return True, entry[0], entry[1]

    def write_value(self, hive, path, name, value_type, value):
        self.values[self.key(hive, path, name)] = (value_type, value)
        self.writes.append(("write", hive, path, name, value_type, value))

    def delete_value(self, hive, path, name):
        self.values.pop(self.key(hive, path, name), None)
        self.writes.append(("delete", hive, path, name))


class WinRegBackend(RegistryBackend):
    """The real thing. Imports `winreg` lazily so this module stays importable
    (and testable) on a non-Windows machine."""

    def __init__(self):
        import winreg  # noqa: PLC0415 - deliberately lazy; see class docstring

        self._winreg = winreg
        self._hives = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
        }
        self._types = {
            "REG_SZ": winreg.REG_SZ,
            "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
            "REG_DWORD": winreg.REG_DWORD,
            "REG_QWORD": winreg.REG_QWORD,
            "REG_BINARY": winreg.REG_BINARY,
            "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
        }
        self._type_names = {v: k for k, v in self._types.items()}

    def _root(self, hive):
        try:
            return self._hives[hive]
        except KeyError:
            raise RegistryError(f"unknown hive {hive!r}") from None

    def read_value(self, hive, path, name):
        winreg = self._winreg
        try:
            with winreg.OpenKey(self._root(hive), path, 0, winreg.KEY_READ) as key:
                value, raw_type = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return False, None, None
        except OSError as e:
            raise RegistryError(f"couldn't read {hive}\\{path}\\{name}: {e}") from e
        type_name = self._type_names.get(raw_type)
        if type_name is None:
            raise RegistryError(
                f"{hive}\\{path}\\{name} holds unsupported type {raw_type}; refusing to "
                f"touch a value this app cannot faithfully restore"
            )
        if type_name == "REG_BINARY" and isinstance(value, bytes):
            value = value.hex()
        elif type_name == "REG_MULTI_SZ":
            value = list(value)
        return True, type_name, value

    def write_value(self, hive, path, name, value_type, value):
        expected = (True, value_type, value)
        winreg = self._winreg
        if value_type not in self._types:
            raise RegistryError(f"unsupported value type {value_type!r}")
        if value_type == "REG_BINARY" and isinstance(value, str):
            value = bytes.fromhex(value)
        elif value_type == "REG_MULTI_SZ" and isinstance(value, list):
            value = [str(v) for v in value]
        try:
            key = winreg.CreateKeyEx(self._root(hive), path, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.SetValueEx(key, name, 0, self._types[value_type], value)
            finally:
                winreg.CloseKey(key)
        except OSError as e:
            raise RegistryError(f"couldn't write {hive}\\{path}\\{name}: {e}") from e

        if self.read_value(hive, path, name) != expected:
            raise RegistryError(f'Windows did not retain the requested value for {hive}\\{path}\\{name}.')

    def delete_value(self, hive, path, name):
        winreg = self._winreg
        try:
            with winreg.OpenKey(self._root(hive), path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return
        except OSError as e:
            raise RegistryError(f"couldn't delete {hive}\\{path}\\{name}: {e}") from e


# -- restorers ----------------------------------------------------------------
#
# A journal entry's `kind` selects the code that puts it back. Registry is
# implemented here; action modules register their own kinds (service start
# types, optional features) so that revert stays one uniform replay rather than
# a per-family special case that someone eventually forgets to write.

_RESTORERS = {}


def register_restorer(kind, restore):
    """restore(entry: dict, context: dict) -> None"""
    _RESTORERS[kind] = restore


def _restore_registry(entry, context):
    backend = context["registry"]
    if entry["existed"]:
        backend.write_value(entry["hive"], entry["path"], entry["name"], entry["type"], entry["value"])
    else:
        # The value was absent before we touched it, so absent is what
        # "restored" means. See the module docstring.
        backend.delete_value(entry["hive"], entry["path"], entry["name"])


register_restorer("registry", _restore_registry)


# -- state file ---------------------------------------------------------------

class StateStore:
    """The on-disk journal, one section per level family.

    Written atomically via a temp file in the same directory, so an interrupted
    write can never leave a half-parsed journal -- which would mean an
    un-revertable machine.
    """

    def __init__(self, path):
        self.path = path
        self._data = self._read()

    def _read(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {}
        except (ValueError, OSError) as exc:
            raise RegistryError(f'The restore journal cannot be read safely: {exc}') from exc
        if not isinstance(data, dict):
            raise RegistryError('The restore journal is not an object; refusing to overwrite it.')
        if data.get('version', STATE_VERSION) != STATE_VERSION:
            raise RegistryError('Unsupported restore journal version; repair with a compatible app version.')
        data.setdefault("version", STATE_VERSION)
        for field in ('families', 'originals'):
            if field in data and not isinstance(data[field], dict):
                raise RegistryError(f'The restore journal has an invalid {field} table.')
        for section in data.get('families', {}).values():
            if not isinstance(section, dict) or not isinstance(section.get('claims', []), list):
                raise RegistryError('The restore journal has an invalid family record.')
            if any(not isinstance(claim, str) for claim in section.get('claims', [])):
                raise RegistryError('The restore journal has an invalid claim.')
        if any(not isinstance(entry, dict) for entry in data.get('originals', {}).values()):
            raise RegistryError('The restore journal has an invalid original record.')
        families = data.get("families")
        data["families"] = families if isinstance(families, dict) else {}
        originals = data.get("originals")
        data["originals"] = originals if isinstance(originals, dict) else {}
        return data

    @contextmanager
    def exclusive(self):
        if os.name != 'nt':
            yield
            return
        import win32event
        import win32api
        import win32security
        import pywintypes
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'D:P(A;;GA;;;SY)(A;;GA;;;BA)', 1)
        mutex = win32event.CreateMutex(sa, False, r'Global\WinHardenState-v1')
        acquired = False
        try:
            result = win32event.WaitForSingleObject(mutex, 30000)
            if result not in (0, 0x80):
                raise RegistryError('Another security change is still running. Retry after it finishes.')
            acquired = True
            self._data = self._read()
            yield
        finally:
            if acquired:
                win32event.ReleaseMutex(mutex)
            win32api.CloseHandle(mutex)

    def save(self):
        self._data["version"] = STATE_VERSION
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".win-harden-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            # World-readable on purpose: the unprivileged status path reads this
            # to report what is applied, so opening a page never needs elevation.
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def family(self, name):
        section = self._data["families"].get(name)
        if not isinstance(section, dict):
            section = {}
        section.setdefault("level", "off")
        claims = section.get("claims")
        section["claims"] = claims if isinstance(claims, list) else []
        notes = section.get("notes")
        section["notes"] = notes if isinstance(notes, dict) else {}
        self._data["families"][name] = section
        return section

    def originals(self):
        """The machine-wide record of what each touched thing looked like BEFORE
        this app first changed it.

        Deliberately not per-family. Two families legitimately set the same
        value -- DNS privacy and Network Exposure both switch LLMNR off -- and
        when the second one applied, a per-family journal captured the first
        one's write and called it the original. Reverting both then restored
        that value instead of deleting it, and whether the machine ended up
        correct depended on the order the families happened to be reverted in.

        One table, first capture wins, so "the original" means the same thing to
        every family.
        """
        return self._data["originals"]

    def other_claimants(self, identity, excluding):
        """Which still-applied families also want `identity` set.

        A value is only put back when nobody is left who asked for it. Reverting
        one family must not undo a setting another applied family still depends
        on.
        """
        holders = []
        for name, section in self._data["families"].items():
            if name == excluding:
                continue
            if identity in (section.get("claims") or []):
                holders.append(name)
        return holders

    def level(self, name):
        return self.family(name)["level"]

    def all_levels(self):
        return {family: self.family(family)["level"] for family in self._data["families"]}

    def snapshot(self):
        """A deep-enough copy for the status payload."""
        return json.loads(json.dumps(self._data))


# -- transaction --------------------------------------------------------------

class Transaction:
    """Scoped to one level family. Records originals on the way in, and can
    replay them exactly on the way out.

    Usage in an action module:

        txn = Transaction(store, "credential", registry=backend)
        txn.begin(level)                 # captures originals iff coming from off
        txn.set_reg("HKLM", path, "RunAsPPL", "REG_DWORD", 1)
        txn.commit()

    A failure part-way through leaves the journal holding everything captured so
    far, so `revert` still puts back what was already changed. That is the
    behaviour we want: a partially-applied level must still be fully undoable.
    """

    def __init__(self, store, family, registry=None, context=None):
        self.store = store
        self.family = family
        self.registry = registry if registry is not None else WinRegBackend()
        self.context = dict(context or {})
        self.context.setdefault("registry", self.registry)
        self._section = store.family(family)
        self._capturing = False
        self._seen = set()

    # -- lifecycle ------------------------------------------------------------

    def begin(self, level):
        """Start applying `level`.

        Claims are reset when the family is currently `off`, so a family that
        stops setting something at a higher level stops claiming it too. The
        recorded originals are NOT reset -- they live in the machine-wide table
        and the first capture is the true one, whichever family made it.
        """
        self._capturing = self._section["level"] == "off"
        self._seen = set()
        self._section["incomplete"] = True
        self.store.save()
        return self._capturing

    def commit(self, level, notes=None):
        # Restore settings dropped when moving to a less restrictive level.
        # Keep failed claims so a later revert can retry, and do not record the
        # requested level until all dropped settings have been restored.
        for identity in list(self._section['claims']):
            if identity in self._seen:
                continue
            if not self.store.other_claimants(identity, excluding=self.family):
                entry = self.store.originals().get(identity)
                if entry is None:
                    raise RegistryError(f'Missing original for {identity}; restoration cannot be verified.')
                restore = _RESTORERS.get(entry.get('kind'))
                if restore is None:
                    raise RegistryError(f'Unknown restore operation for {identity}')
                restore(entry, self.context)
                self.store.originals().pop(identity, None)
            self._section['claims'].remove(identity)
            self.store.save()
        self._section["level"] = level
        self._section.pop("incomplete", None)
        if notes is not None:
            self._section["notes"] = notes
        self.store.save()

    # -- recording ------------------------------------------------------------

    def _claimed(self, identity):
        return identity in self._section["claims"]

    def record(self, kind, identity, entry):
        """Record one original in the machine-wide table, and claim it for this
        family.

        Two dedupes, doing different jobs:

          * The originals table takes the FIRST capture and never overwrites it.
            That is what makes stepping Basic -> Balanced -> Strict safe (both
            touch RunAsPPL), and what stops a second family capturing the first
            family's write as though it were the machine's original.
          * The claim list is per-family and says "this family wants this set".
            Revert consults every family's claims before putting anything back.
        """
        originals = self.store.originals()
        self._seen.add(identity)
        captured = identity not in originals
        if captured:
            record = dict(entry)
            record["kind"] = kind
            record["_id"] = identity
            originals[identity] = record
        if not self._claimed(identity):
            self._section["claims"].append(identity)
        # Flush the original BEFORE the corresponding external mutation. A
        # process crash must not lose the only record of the previous value.
        self.store.save()
        return captured

    def capture_reg(self, hive, path, name):
        """Record the current state of one value without changing it."""
        if hive not in HIVES:
            raise RegistryError(f"unknown hive {hive!r}")
        identity = f"{hive}\\{path.rstrip(chr(92)).lower()}\\{name.lower()}"
        self._seen.add(identity)
        if identity in self.store.originals() and self._claimed(identity):
            return
        existed, value_type, value = self.registry.read_value(hive, path, name)
        self.record("registry", identity, {
            "hive": hive,
            "path": path,
            "name": name,
            "existed": existed,
            "type": value_type,
            "value": value,
        })

    def set_reg(self, hive, path, name, value_type, value):
        """Capture-then-write. The only way this module writes the registry, so
        there is no path that changes a value without recording it first."""
        if value_type not in REG_TYPES:
            raise RegistryError(f"unsupported value type {value_type!r}")
        self.capture_reg(hive, path, name)
        self.registry.write_value(hive, path, name, value_type, value)

    def delete_reg(self, hive, path, name):
        self.capture_reg(hive, path, name)
        self.registry.delete_value(hive, path, name)

    # -- revert ---------------------------------------------------------------

    def revert(self):
        """Replay the journal in reverse and clear it.

        Reverse order matters wherever entries depend on each other -- a service
        stopped before it was disabled has to be re-enabled before it is
        restarted. Each entry is attempted even if an earlier one failed, so one
        unrestorable value cannot strand every setting after it; the failures are
        collected and returned.

        Returns a list of (entry, exception) for whatever could not be restored;
        empty means the machine is back exactly where it started.
        """
        originals = self.store.originals()
        failures = []
        kept = []

        # Mark this family as off first, so other_claimants() does not count it
        # as a claimant of its own values.
        self._section["incomplete"] = True
        self.store.save()
        was_level, self._section["level"] = self._section["level"], "off"

        for identity in reversed(self._section["claims"]):
            if self.store.other_claimants(identity, excluding=self.family):
                # Another applied family still wants this set. Leave it alone and
                # drop our claim; it will be restored when the last claimant goes.
                continue
            entry = originals.get(identity)
            if entry is None:
                failures.append(({'_id': identity}, RegistryError('The original value was not recorded.')))
                kept.append(identity)
                continue
            restore = _RESTORERS.get(entry.get("kind"))
            if restore is None:
                failures.append((entry, RegistryError(
                    f"no restorer registered for journal entry kind {entry.get('kind')!r}"
                )))
                kept.append(identity)
                continue
            try:
                restore(entry, self.context)
            except Exception as e:  # noqa: BLE001 - one bad entry must not strand the rest
                failures.append((entry, e))
                kept.append(identity)
            else:
                originals.pop(identity, None)

        # Anything that could not be restored keeps its claim and its recorded
        # original, so a later revert can retry it. Dropping either would quietly
        # turn a failed restore into a permanent change.
        self._section["claims"] = kept
        if failures:
            self._section["level"] = was_level
        else:
            self._section.pop("incomplete", None)
        self._section["notes"] = {}
        self.store.save()
        return failures
