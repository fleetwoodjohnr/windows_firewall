"""Networks: which profile each network gets, and which resolver it uses.

Port of the Fedora app's Network Profiles page. The Linux version assigned a
firewalld zone to each saved NetworkManager connection; here it assigns Windows'
network category, which is the thing that decides which firewall profile applies.

Two honest limitations the page states rather than works around:

  * Only Public and Private can be set. Domain is chosen by Windows when the
    machine is joined to a domain it can reach, and no application can change it.
  * Windows remembers the category per network itself, so there is no saved-list
    to manage the way NetworkManager had one. This page shows what is connected
    now, which is the only thing Windows will let anything change.
"""

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from broker.dns_providers import PROVIDERS, get as get_provider

from ..widgets.page import Banner, Group, Page

CATEGORY_HELP = {
    "Public": (
        "Windows applies the Public firewall profile, which is the restrictive one: this PC does "
        "not announce itself and does not accept file sharing. The right choice for any network "
        "you do not control."
    ),
    "Private": (
        "Windows applies the Private profile, which allows discovery and file sharing so home "
        "devices can find each other. Only use it on a network where you trust every device — "
        "including the ones you did not set up."
    ),
    "DomainAuthenticated": (
        "Windows selected the Domain profile because this machine is joined to a domain and can "
        "reach it. This cannot be changed by an application; domain policy decides it."
    ),
}


class NetworkRow(QWidget):
    """One adapter: its category and its resolver."""

    def __init__(self, interface, on_category, on_provider, parent=None):
        super().__init__(parent)
        self.interface = interface
        self._on_category = on_category
        self._on_provider = on_provider
        self._syncing = False

        index = interface.get("index")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(6)

        title = QLabel(interface.get("name") or f"Adapter {index}", self)
        title.setObjectName("rowTitle")
        layout.addWidget(title)

        subtitle = QLabel(interface.get("description") or "", self)
        subtitle.setObjectName("rowSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        controls = QHBoxLayout()
        controls.setSpacing(10)

        self.category_combo = QComboBox(self)
        category = interface.get("category")
        if category == "DomainAuthenticated":
            # Not a choice we are allowed to make. Shown, and disabled, rather
            # than hidden -- the user should see why it is fixed.
            self.category_combo.addItem("Domain (set by Windows)", "DomainAuthenticated")
            self.category_combo.setEnabled(False)
        else:
            self.category_combo.addItem("Public", "Public")
            self.category_combo.addItem("Private", "Private")
        controls.addWidget(self.category_combo, 1)

        self.provider_combo = QComboBox(self)
        for provider in PROVIDERS:
            self.provider_combo.addItem(provider.label.split(" — ")[0], provider.id)
        controls.addWidget(self.provider_combo, 1)
        layout.addLayout(controls)

        self.detail = QLabel("", self)
        self.detail.setObjectName("rowDetail")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)

        self.sync(interface)
        self.category_combo.currentIndexChanged.connect(self._category_changed)
        self.provider_combo.currentIndexChanged.connect(self._provider_changed)

    def sync(self, interface):
        """Point the controls at what the machine reports. Never applies."""
        self._syncing = True
        self.interface = interface

        category = interface.get("category")
        index = self.category_combo.findData(category)
        if index >= 0:
            self.category_combo.setCurrentIndex(index)

        servers = interface.get("dnsServers") or []
        matched = "automatic"
        for provider in PROVIDERS:
            if provider.ipv4 and set(provider.ipv4) & set(servers):
                matched = provider.id
                break
        provider_index = self.provider_combo.findData(matched)
        if provider_index >= 0:
            self.provider_combo.setCurrentIndex(provider_index)

        encrypted = interface.get("dohEnabled")
        lines = [CATEGORY_HELP.get(category, "")]
        if servers:
            lines.append(
                ("Lookups are encrypted." if encrypted
                 else "Lookups are NOT encrypted — they leave this PC in plain text.")
                + " Resolver: " + ", ".join(servers) + "."
            )
        else:
            lines.append("Using whichever resolver this network hands out.")
        self.detail.setText("\n\n".join(part for part in lines if part))
        self._syncing = False

    def _category_changed(self, _index):
        if self._syncing:
            return
        wanted = self.category_combo.currentData()
        self.sync(self.interface)   # non-optimistic: the result moves it
        self._on_category(self.interface, wanted)

    def _provider_changed(self, _index):
        if self._syncing:
            return
        wanted = self.provider_combo.currentData()
        self.sync(self.interface)
        self._on_provider(self.interface, wanted)


class NetworksPage(Page):
    TITLE = "Networks"
    SUBTITLE = (
        "Each connected adapter: whether Windows treats its network as public or private, and "
        "which resolver answers its lookups."
    )

    def __init__(self, window, parent=None):
        super().__init__(self.TITLE, self.SUBTITLE, parent)
        self.window = window
        self.broker = window.broker
        self.powershell = window.powershell

        self.banner = Banner(parent=self)
        self.banner.hide_message()
        self.add(self.banner)

        self.group = Group(
            "Connected adapters",
            "Windows remembers a network's category itself, so only what is connected now can be "
            "changed. Domain is chosen by Windows and cannot be set here.",
            self,
        )
        self.placeholder = QLabel("Reading network adapters…", self.group)
        self.placeholder.setObjectName("rowDetail")
        self.placeholder.setWordWrap(True)
        self.group.add(self.placeholder)
        self.add(self.group)
        self.add_stretch()

        self._rows = {}

    # -- state ----------------------------------------------------------------

    def refresh(self):
        def on_result(result, error):
            if error is not None:
                self.banner.show_message(
                    "Network adapters could not be read", str(error), tone="error")
                return
            self.banner.hide_message()
            self._render((result or {}).get("interfaces") or [])

        self.powershell.run("status-network.ps1", None, on_result)

    def _render(self, interfaces):
        connected = [i for i in interfaces if i.get("index") is not None]
        if not connected:
            self.placeholder.setText("No connected network adapter was reported.")
            self.placeholder.setVisible(True)
            for row in self._rows.values():
                row.setParent(None)
                row.deleteLater()
            self._rows = {}
            return

        self.placeholder.setVisible(False)
        seen = set()
        for interface in connected:
            index = interface["index"]
            seen.add(index)
            row = self._rows.get(index)
            if row is None:
                row = NetworkRow(interface, self._on_category, self._on_provider, self.group)
                self._rows[index] = row
                self.group.add(row)
            else:
                row.sync(interface)

        for index in list(self._rows):
            if index not in seen:
                row = self._rows.pop(index)
                row.setParent(None)
                row.deleteLater()

    # -- changes --------------------------------------------------------------

    def _on_category(self, interface, category):
        def on_result(_result, error):
            if error is not None:
                self.banner.show_message(
                    f"'{interface.get('name')}' could not be set to {category}",
                    str(error), tone="error")
                return
            self.banner.show_message(
                f"'{interface.get('name')}' is now {category}",
                CATEGORY_HELP.get(category, ""), tone="ok")
            self.refresh()

        # Setting a network category is a privileged change, so it goes through
        # the broker rather than being run in this process.
        self.broker.set_network_category(interface["index"], category, on_result)

    def _on_provider(self, interface, provider_id):
        def on_result(_result, error):
            if error is not None:
                self.banner.show_message(
                    "The resolver could not be changed", str(error), tone="error")
                return
            provider = get_provider(provider_id)
            self.banner.show_message(
                f"'{interface.get('name')}' now uses {provider.label.split(' — ')[0]}",
                provider.detail, tone="ok")
            self.refresh()

        self.broker.set_dns_provider(provider_id, interface["index"], on_result)


PAGE_CLASS = NetworksPage
