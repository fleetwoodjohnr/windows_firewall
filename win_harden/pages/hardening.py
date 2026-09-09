"""Hardening: network exposure, credentials, DNS privacy and TLS.

The direct descendant of the Fedora app's Hardening page, widened. Four level
selectors, the resolver picker, and individual switches for the components a
level turns off wholesale but which someone may want back.

The resolver picker is kept separate from the DNS level for the reason the
original gives (`data/dns_levels.py:1-15`): the level says how lookups are
protected, the provider says who answers them, and they fail differently. On a
VPN the right answer is usually still Automatic, because pinning a public
resolver sends lookups around the tunnel rather than through it.
"""

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from broker.dns_providers import PROVIDERS, get as get_provider

from ..widgets.page import Group, KeyValueRow
from ._levels_page import LevelFamilyPage

# Individually switchable components, with why you might want each one back on.
TOGGLES = (
    ("openssh-server", "OpenSSH server",
     "Lets other machines log into this PC over SSH. On a desktop that never accepts remote "
     "logins, switching the server off beats any amount of hardening applied to it."),
    ("rdp", "Remote Desktop",
     "Lets you connect to this PC's desktop from elsewhere. Switched off by the Network "
     "Exposure level from Balanced upward; turn it back on here if you use it."),
    ("winrm", "Windows Remote Management",
     "Remote PowerShell and management access. Rarely used on a personal machine."),
    ("remote-registry", "Remote Registry",
     "Lets other machines read and change this one's registry. There is no good reason for "
     "this to be on for a desktop."),
    ("smb1", "SMBv1 file sharing",
     "The thirty-year-old file sharing protocol behind WannaCry and NotPetya. Only needed to "
     "reach shares on Windows XP-era machines or very old NAS boxes."),
)


class ToggleWidget(QWidget):
    """One switchable component, non-optimistic like everything else."""

    def __init__(self, key, label, description, on_change, parent=None):
        super().__init__(parent)
        from PySide6.QtWidgets import QCheckBox

        self.key = key
        self._on_change = on_change
        self._syncing = False
        self._system_state = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 6, 0, 6)
        layout.setSpacing(2)

        top = QHBoxLayout()
        title = QLabel(label, self)
        title.setObjectName("rowTitle")
        top.addWidget(title, 1)
        self.check = QCheckBox(self)
        self.check.clicked.connect(self._on_clicked)
        top.addWidget(self.check, 0)
        layout.addLayout(top)

        body = QLabel(description, self)
        body.setObjectName("rowDetail")
        body.setWordWrap(True)
        layout.addWidget(body)

    def set_state(self, enabled):
        self._syncing = True
        self._system_state = bool(enabled)
        self.check.setChecked(bool(enabled))
        self._syncing = False

    def _on_clicked(self, requested):
        if self._syncing:
            return
        self.set_state(self._system_state)   # put it back; the result moves it
        self.check.setEnabled(False)

        def done(ok):
            self.check.setEnabled(True)
            if ok:
                self.set_state(requested)

        self._on_change(self.key, requested, done)


class HardeningPage(LevelFamilyPage):
    FAMILIES = ("exposure", "credential", "dns", "tls")
    TITLE = "Hardening"
    SUBTITLE = (
        "What this PC exposes to the network, how well its credentials are protected, whether "
        "its DNS lookups are private, and how weak a connection it will accept."
    )

    def build_extras(self):
        self._build_resolver_group()
        self._build_toggle_group()

    # -- resolver -------------------------------------------------------------

    def _build_resolver_group(self):
        group = Group(
            "Who answers your lookups",
            "Separate from the DNS level above: the level decides how lookups are protected, "
            "this decides who answers them.",
            self,
        )

        self.provider_combo = QComboBox(group)
        for provider in PROVIDERS:
            self.provider_combo.addItem(provider.label, provider.id)
        self.provider_combo.currentIndexChanged.connect(self._on_provider_selected)
        group.add(self.provider_combo)

        self.provider_detail = QLabel("", group)
        self.provider_detail.setObjectName("rowDetail")
        self.provider_detail.setWordWrap(True)
        group.add(self.provider_detail)

        self.provider_status = KeyValueRow("Currently pinned on", "—")
        group.add(self.provider_status)

        self._syncing_provider = False
        self._show_provider_detail(self.settings.dns_provider)
        self.add(group)

    def _show_provider_detail(self, provider_id):
        provider = get_provider(provider_id)
        index = self.provider_combo.findData(provider.id)
        if index >= 0 and self.provider_combo.currentIndex() != index:
            self._syncing_provider = True
            self.provider_combo.setCurrentIndex(index)
            self._syncing_provider = False
        self.provider_detail.setText(provider.detail)

    def _on_provider_selected(self, _index):
        if self._syncing_provider:
            return
        provider_id = self.provider_combo.currentData()
        self._show_provider_detail(provider_id)

        interfaces = self._interfaces()
        if not interfaces:
            self.banner.show_message(
                "No network adapter to pin a resolver on",
                "No connected adapter was reported, so there is nothing to apply this to.",
                tone="warning")
            return

        remaining = {"count": len(interfaces), "error": None}

        def on_one(_result, error):
            remaining["count"] -= 1
            if error is not None:
                remaining["error"] = error
            if remaining["count"]:
                return
            if remaining["error"] is not None:
                self.banner.show_message(
                    "The resolver could not be changed", str(remaining["error"]), tone="error")
                return
            # Only recorded once it actually landed on every adapter.
            self.settings.dns_provider = provider_id
            self.banner.show_message(
                f"Lookups now go to {get_provider(provider_id).label.split(' — ')[0]}",
                "Applied to every connected adapter.", tone="ok")
            self.refresh()

        for index in interfaces:
            self.broker.set_dns_provider(provider_id, index, on_one)

    def _interfaces(self):
        return [i["index"] for i in getattr(self, "_live_interfaces", []) if i.get("index") is not None]

    # -- toggles --------------------------------------------------------------

    def _build_toggle_group(self):
        group = Group(
            "Individual components",
            "A level switches several of these together. Change one here when a level is right "
            "except for a single component.",
            self,
        )
        self.toggle_widgets = {}
        for key, label, description in TOGGLES:
            widget = ToggleWidget(key, label, description, self._on_toggle, group)
            self.toggle_widgets[key] = widget
            group.add(widget)
        self.add(group)

    def _on_toggle(self, key, enabled, done):
        def on_result(_result, error):
            if error is not None:
                # A guard refusal arrives here too -- disabling Remote Desktop
                # from a Remote Desktop session. It is explained, not treated as
                # a fault.
                from ..backend.errors import GuardRefused

                self.banner.show_message(
                    f"'{key}' was not changed", str(error),
                    tone="warning" if isinstance(error, GuardRefused) else "error")
                done(False)
                return
            self.banner.show_message(
                f"'{key}' is now {'on' if enabled else 'off'}", "", tone="ok")
            done(True)
            self.refresh()

        self.broker.set_toggle(key, enabled, on_result)

    # -- status ---------------------------------------------------------------

    def on_status(self, status):
        live = status.get("live") or {}
        dns = live.get("dns") or {}
        exposure = live.get("exposure") or {}

        self._live_interfaces = dns.get("interfaces") or []
        encrypted = [i for i in self._live_interfaces if i.get("dohEnabled")]
        if not self._live_interfaces:
            self.provider_status.set_value("No adapter reported", "warn")
        else:
            self.provider_status.set_value(
                f"{len(encrypted)} of {len(self._live_interfaces)} adapters using encrypted DNS",
                "ok" if len(encrypted) == len(self._live_interfaces) else "warn")

        services = {s.get("name", "").lower(): s for s in (exposure.get("services") or [])}
        features = {f.get("name", "").lower(): f for f in (exposure.get("features") or [])}

        state_for = {
            "openssh-server": (services.get("sshd") or {}).get("running"),
            "rdp": (None if exposure.get("rdpDenied") is None
                    else not bool(exposure.get("rdpDenied"))),
            "winrm": (services.get("winrm") or {}).get("running"),
            "remote-registry": (services.get("remoteregistry") or {}).get("running"),
            "smb1": (features.get("smb1protocol") or {}).get("enabled"),
        }
        for key, widget in self.toggle_widgets.items():
            widget.set_state(bool(state_for.get(key)))


PAGE_CLASS = HardeningPage
