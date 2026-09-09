"""Firewall Rules: what this PC accepts, per profile.

Port of the Fedora app's Zone Editor, adapted to the structural difference that
matters most: Windows has exactly three firewall profiles -- Domain, Private,
Public -- and exactly one is in force at a time, chosen by Windows from the
network you are on. There is no equivalent of firewalld's arbitrary zones, so
"pick any zone" becomes "pick one of three".

What firewalld called services, Windows calls rule groups, and they play the same
role. One difference the UI has to be honest about: a Windows group can be
*partially* enabled, because it is several rules rather than one switch. That is
shown as a third state rather than rounded to on or off, because rounding would
make the switch lie about what is actually open.
"""

from PySide6.QtWidgets import QComboBox, QLabel, QLineEdit

from ..data.rule_groups import describe, is_essential
from ..widgets.confirm import confirm
from ..widgets.page import Banner, Group, Page
from ..widgets.toggle_row import ToggleRow

PROFILES = (
    ("Public", "Public — cafés, hotels, anywhere you do not control",
     "The restrictive profile, and the one to keep tight. Windows picks it for any network you "
     "have not marked as private."),
    ("Private", "Private — your home or office network",
     "More permissive by design, so file sharing and device discovery work. Still worth reviewing: "
     "'private' means you trust every device on it, including the ones you did not set up."),
    ("Domain", "Domain — a corporate network with a domain controller",
     "Windows selects this by itself when the machine is domain-joined and can reach its domain. "
     "It usually cannot be changed here, because domain policy sets it."),
)


class FirewallPage(Page):
    TITLE = "Firewall Rules"
    SUBTITLE = (
        "Which groups of inbound rules are open, for each of Windows' three firewall profiles. "
        "Only one profile is in force at a time — whichever matches the network you are on."
    )

    def __init__(self, window, parent=None):
        super().__init__(self.TITLE, self.SUBTITLE, parent)
        self.window = window
        self.broker = window.broker
        self.powershell = window.powershell

        self.banner = Banner(parent=self)
        self.banner.hide_message()
        self.add(self.banner)

        self._build_picker()
        self._build_groups()
        self.add_stretch()
        self._rows = {}

    def _build_picker(self):
        group = Group("Profile", "", self)
        self.profile_combo = QComboBox(group)
        for profile_id, label, _detail in PROFILES:
            self.profile_combo.addItem(label, profile_id)
        self.profile_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        group.add(self.profile_combo)

        self.profile_detail = QLabel(PROFILES[0][2], group)
        self.profile_detail.setObjectName("rowDetail")
        self.profile_detail.setWordWrap(True)
        group.add(self.profile_detail)
        self.add(group)

    def _build_groups(self):
        self.groups_group = Group(
            "Inbound rule groups",
            "A group is on only when every rule in it is enabled. 'Partly on' means some rules "
            "are open and some are not — switching it will apply to all of them.",
            self,
        )
        self.search = QLineEdit(self.groups_group)
        self.search.setPlaceholderText("Filter groups…")
        self.search.textChanged.connect(self._apply_filter)
        self.groups_group.add(self.search)

        self.groups_placeholder = QLabel("Reading firewall rules…", self.groups_group)
        self.groups_placeholder.setObjectName("rowDetail")
        self.groups_placeholder.setWordWrap(True)
        self.groups_group.add(self.groups_placeholder)
        self.add(self.groups_group)

    # -- state ----------------------------------------------------------------

    def current_profile(self):
        return self.profile_combo.currentData() or "Public"

    def refresh(self):
        index = self.profile_combo.currentIndex()
        if 0 <= index < len(PROFILES):
            self.profile_detail.setText(PROFILES[index][2])

        def on_result(result, error):
            if error is not None:
                self.banner.show_message(
                    "Firewall rules could not be read", str(error), tone="error")
                return
            self.banner.hide_message()
            self._render_groups((result or {}).get("groups") or [])

        self.powershell.run("list-rule-groups.ps1", {"Profile": self.current_profile()}, on_result)

    def _render_groups(self, groups):
        for row in self._rows.values():
            row.setParent(None)
            row.deleteLater()
        self._rows = {}

        if not groups:
            self.groups_placeholder.setText("No inbound rule groups were reported for this profile.")
            self.groups_placeholder.setVisible(True)
            return
        self.groups_placeholder.setVisible(False)

        for entry in groups:
            name = entry.get("name")
            if not name:
                continue
            info = describe(name)
            state = entry.get("state")
            if state == "partial":
                info = type(info)(
                    label=info.label,
                    summary=f"Partly on — {entry.get('enabled')} of {entry.get('total')} rules "
                            f"are enabled. {info.summary}",
                    recommendation=info.recommendation,
                    risk=info.risk,
                    category=info.category,
                )
            row = ToggleRow(name, info, state == "on", self._on_toggle,
                            self._on_toggle_error, self.groups_group)
            self._rows[name] = row
            self.groups_group.add(row)
        self._apply_filter(self.search.text())

    def _apply_filter(self, query):
        for row in self._rows.values():
            row.setVisible(row.matches(query))

    # -- changes --------------------------------------------------------------

    def _on_toggle(self, name, enabled, done):
        if not enabled and is_essential(name):
            # Turning this off does not harden the machine; it breaks its
            # ability to use a network at all, and then looks like a bug in this
            # app rather than a choice.
            confirm(
                self.window,
                f"Really switch off {name}?",
                f"{name} carries the traffic Windows itself needs to use a network — DHCP, IPv6 "
                f"and ICMP among it.\n\nSwitching it off does not make this PC safer. It makes it "
                f"unable to get an address or reach anything, and the symptom will look like a "
                f"broken network rather than a firewall rule.",
                "Switch it off anyway",
                lambda: self._send_toggle(name, enabled, done),
                lambda: done(False),
                destructive=True,
            )
            return
        self._send_toggle(name, enabled, done)

    def _send_toggle(self, name, enabled, done):
        """Rule-group changes are a privileged firewall write, so they go
        through the broker like every other change rather than being run in this
        unelevated process."""

        def on_result(_result, error):
            if error is not None:
                done(False, error)
                return
            done(True)
            self.refresh()

        self.broker.set_rule_group(self.current_profile(), name, enabled, on_result)

    def _on_toggle_error(self, name, _requested, error):
        self.banner.show_message(f"'{name}' could not be changed", str(error), tone="error")


PAGE_CLASS = FirewallPage
