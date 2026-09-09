"""App-side preferences, persisted as JSON.

Ported from the Fedora app's `settings.py`, minus GObject: plain properties with
a save-on-change hook. The load-time type coercion is kept, for the reason the
original gives -- a settings file edited by hand, or written by an older
version, must not be able to hand a page the wrong type.

What is stored here is only ever *preference*. System state lives in the
registry and in the broker's journal, and is always re-read from there rather
than trusted from this file.
"""

import json
import os

APP_DIR_NAME = "win-harden"


def config_dir():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, APP_DIR_NAME)


class AppSettings:
    # name -> default. Both load and save iterate this, so adding a setting means
    # adding one line here and nothing else.
    _KEYS = {
        "dns_provider": "automatic",
        "dns_pinned_interfaces": "[]",
        "show_advanced_rules": False,
        "last_page": "dashboard",
        "confirm_strict": True,
    }

    def __init__(self, path=None):
        self.path = path or os.path.join(config_dir(), "settings.json")
        self._loading = False
        self._values = dict(self._KEYS)
        self._load()

    def __getattr__(self, name):
        if name.startswith("_") or name not in type(self)._KEYS:
            raise AttributeError(name)
        return self._values[name]

    def __setattr__(self, name, value):
        if name.startswith("_") or name in ("path",) or name not in type(self)._KEYS:
            super().__setattr__(name, value)
            return
        self._values[name] = value
        if not self._loading:
            self._save()

    def _load(self):
        data = {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            pass
        if not isinstance(data, dict):
            data = {}
        self._loading = True
        for name, default in self._KEYS.items():
            value = data.get(name, default)
            # A value of the wrong type falls back to the default rather than
            # being coerced. bool("garbage") is True, which would silently turn a
            # corrupt file into an enabled setting -- the one direction a
            # settings bug must never fail in.
            self._values[name] = value if type(value) is type(default) else default
        self._loading = False

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._values, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            # A settings file we cannot write is a lost preference, never a
            # reason to fail the operation the user actually asked for.
            pass

    # -- JSON-backed list accessors -------------------------------------------

    @staticmethod
    def _decode_list(raw):
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return []
        return [str(item) for item in value] if isinstance(value, list) else []

    def get_pinned_interfaces(self):
        return self._decode_list(self.dns_pinned_interfaces)

    def set_pinned_interfaces(self, indexes):
        self.dns_pinned_interfaces = json.dumps(sorted({str(i) for i in indexes}))
