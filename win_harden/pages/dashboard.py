"""Dashboard: what this PC's protection actually looks like right now.

Port of the Fedora app's Dashboard. Same four jobs -- show the live state, offer
panic mode, and list actionable suggestions -- with Defender's status added,
because on Windows that is the first thing anyone wants to know.

The findings list is the part worth care. It only shows a finding for a family
whose live state actually came back from the machine (`findings._was_read`), and
it says out loud which families it could not read. A dashboard that shows a clean
bill of health because it could not read anything is worse than one that shows
nothing at all.
"""

from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ..data.findings import applicable, unreadable_families
from ..widgets.confirm import confirm
from ..widgets.page import Banner, Group, KeyValueRow, Page, unknown_label

SEVERITY_TONE = {"high": "bad", "medium": "warn", "low": "ok"}
SEVERITY_LABEL = {"high": "Important", "medium": "Worth doing", "low": "Minor"}


class FindingWidget(QWidget):
    def __init__(self, finding, on_go, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(10)

        dot = QLabel("●", self)
        dot.setObjectName("riskDot")
        dot.setProperty("risk", SEVERITY_TONE.get(finding.severity, "warn"))
        dot.setToolTip(SEVERITY_LABEL.get(finding.severity, ""))
        top.addWidget(dot, 0)

        title = QLabel(finding.title, self)
        title.setObjectName("rowTitle")
        title.setWordWrap(True)
        top.addWidget(title, 1)

        if finding.fix_page:
            button = QPushButton("Fix this", self)
            button.setProperty("accent", finding.severity == "high")
            button.clicked.connect(lambda: on_go(finding))
            top.addWidget(button, 0)
        layout.addLayout(top)

        body = QLabel(finding.detail, self)
        body.setObjectName("rowDetail")
        body.setWordWrap(True)
        layout.addWidget(body)


class DashboardPage(Page):
    TITLE = "Dashboard"
    SUBTITLE = "What is protecting this PC right now, and what is not."

    def __init__(self, window, parent=None):
        super().__init__(self.TITLE, self.SUBTITLE, parent)
        self.window = window
        self.broker = window.broker

        self.banner = Banner(parent=self)
        self.banner.hide_message()
        self.add(self.banner)

        self._build_overview()
        self._build_panic()
        self._build_findings()
        self.add_stretch()

    # -- construction ---------------------------------------------------------

    def _build_overview(self):
        group = Group("At a glance", "Read from the machine, every time this page is opened.", self)
        self.rows = {
            "firewall": KeyValueRow("Firewall"),
            "network": KeyValueRow("Current network"),
            "defender": KeyValueRow("Real-time protection"),
            "tamper": KeyValueRow("Tamper Protection"),
            "bitlocker": KeyValueRow("Drive encryption"),
            "asr": KeyValueRow("ASR rules enforcing"),
            "dns": KeyValueRow("Encrypted DNS"),
        }
        for row in self.rows.values():
            group.add(row)
        self.add(group)

    def _build_panic(self):
        group = Group(
            "Panic mode",
            "Blocks every connection, in and out, on all three firewall profiles. For when you "
            "think something is wrong and want the machine off the network immediately.",
            self,
        )
        row = QWidget(group)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel("Block all network traffic", row)
        label.setObjectName("rowTitle")
        layout.addWidget(label, 1)
        self.panic_switch = QCheckBox(row)
        self.panic_switch.clicked.connect(self._on_panic_clicked)
        layout.addWidget(self.panic_switch, 0)
        group.add(row)

        note = QLabel(
            "This drops connections that are already open. Anything downloading stops, and if you "
            "are connected to this PC remotely, that session ends immediately.",
            group,
        )
        note.setObjectName("rowDetail")
        note.setWordWrap(True)
        group.add(note)
        self.add(group)

    def _build_findings(self):
        self.findings_group = Group(
            "Suggestions",
            "Specific things about this machine, each with the one action that fixes it.",
            self,
        )
        self.findings_placeholder = QLabel("Reading the machine…", self.findings_group)
        self.findings_placeholder.setObjectName("rowDetail")
        self.findings_placeholder.setWordWrap(True)
        self.findings_group.add(self.findings_placeholder)
        self._finding_widgets = []
        self.add(self.findings_group)

    # -- panic mode -----------------------------------------------------------

    def _on_panic_clicked(self, requested):
        # Non-optimistic, like every other control: put it back and let the
        # result move it.
        self.panic_switch.setChecked(not requested)
        if not requested:
            self._apply_panic(False)
            return

        confirm(
            self.window,
            "Block all network traffic?",
            "Every connection in and out will be blocked on all three firewall profiles.\n\n"
            "Downloads and calls in progress will stop. If you are connected to this PC over "
            "Remote Desktop, that session ends immediately and you will need physical access to "
            "turn this back off.",
            "Block everything",
            lambda: self._apply_panic(True),
            destructive=True,
        )

    def _apply_panic(self, enabled):
        self.panic_switch.setEnabled(False)

        def on_result(_result, error):
            self.panic_switch.setEnabled(True)
            if error is not None:
                self.banner.show_message("Panic mode could not be changed", str(error), tone="error")
                return
            self.panic_switch.setChecked(enabled)
            self.banner.show_message(
                "All traffic is blocked" if enabled else "Normal traffic restored",
                "Turn this off here when you are done." if enabled else "",
                tone="warning" if enabled else "ok")
            self.refresh()

        self.broker.set_toggle("panic-mode", enabled, on_result)

    # -- findings -------------------------------------------------------------

    def _on_go_to_fix(self, finding):
        """Send the user to the control that fixes this, rather than describing
        where it is."""
        from ..window import PAGES  # noqa: PLC0415 - avoids an import cycle

        for index, (page_id, _label, _tip) in enumerate(PAGES):
            if page_id == finding.fix_page:
                self.window.nav.setCurrentRow(index)
                return

    def _render_findings(self, status):
        for widget in self._finding_widgets:
            widget.setParent(None)
            widget.deleteLater()
        self._finding_widgets = []

        matched = applicable(status)
        unreadable = unreadable_families(status)

        if not matched and not unreadable:
            self.findings_placeholder.setText(
                "Nothing to flag. Every check this app makes came back clean.")
            self.findings_placeholder.setVisible(True)
            return

        if not matched and unreadable:
            self.findings_placeholder.setText(
                "Nothing was flagged, but " + ", ".join(unreadable) + " could not be read, so "
                "this is not a clean bill of health — those areas were not checked at all.")
            self.findings_placeholder.setVisible(True)
            return

        self.findings_placeholder.setVisible(bool(unreadable))
        if unreadable:
            self.findings_placeholder.setText(
                "Not checked, because these could not be read: " + ", ".join(unreadable) + ".")

        for finding in matched:
            widget = FindingWidget(finding, self._on_go_to_fix, self.findings_group)
            self._finding_widgets.append(widget)
            self.findings_group.add(widget)

    # -- status ---------------------------------------------------------------

    def refresh(self):
        def on_status(result, error):
            if error is not None:
                self.banner.show_message(
                    "This PC could not be read",
                    f"{error}\n\nNothing below has been verified. Do not treat an empty "
                    f"suggestions list as a clean result.",
                    tone="error")
                self._render_findings({})
                return
            self.banner.hide_message()
            self._render_status(result or {})

        self.broker.status(on_status)

    def _render_status(self, status):
        live = status.get("live") or {}
        defender = live.get("defender") or {}
        exploit = live.get("exploit") or {}
        dns = live.get("dns") or {}

        realtime = defender.get("realtimeProtection")
        self.rows["defender"].set_value(
            unknown_label(realtime), "ok" if realtime else "bad")

        tampered = status.get("tamperProtected")
        self.rows["tamper"].set_value(
            unknown_label(tampered, yes="On (blocks changes)", no="Off"),
            "warn" if tampered else "ok")

        rules = defender.get("asrRules") or {}
        blocking = sum(1 for action in rules.values() if action == "block")
        self.rows["asr"].set_value(
            f"{blocking} of 18" if rules else "None configured",
            "ok" if blocking >= 8 else "bad" if not blocking else "warn")

        volumes = exploit.get("bitlocker") or []
        protected = [v for v in volumes if v.get("protectionOn")]
        if not volumes:
            self.rows["bitlocker"].set_value("Not reported", "warn")
        elif not protected:
            self.rows["bitlocker"].set_value("Off", "bad")
        elif any(not v.get("recoveryProtectorPresent") for v in protected):
            self.rows["bitlocker"].set_value("On, no recovery password protector", "bad")
        else:
            self.rows["bitlocker"].set_value("On, recovery protector present", "ok")

        interfaces = dns.get("interfaces") or []
        encrypted = [i for i in interfaces if i.get("dohEnabled")]
        self.rows["dns"].set_value(
            "Not reported" if not interfaces
            else f"{len(encrypted)} of {len(interfaces)} adapters",
            "ok" if interfaces and len(encrypted) == len(interfaces) else "warn")

        self._render_findings(status)
        self._refresh_firewall()

    def _refresh_firewall(self):
        def on_result(result, error):
            if error is not None:
                self.rows["firewall"].set_value("Could not be read", "warn")
                return
            profiles = (result or {}).get("profiles") or []
            enabled = [p for p in profiles if p.get("enabled")]
            self.rows["firewall"].set_value(
                f"On for {len(enabled)} of {len(profiles)} profiles" if profiles else "Not reported",
                "ok" if profiles and len(enabled) == len(profiles) else "bad")

            panic = (result or {}).get("panicMode")
            self.panic_switch.setChecked(bool(panic))

            active = (result or {}).get("activeNetworks") or []
            if active:
                first = active[0]
                self.rows["network"].set_value(
                    f"{first.get('name', 'Unknown')} — {first.get('category', '?')}",
                    "ok" if first.get("category") == "Public" else "warn")
            else:
                self.rows["network"].set_value("Not connected", "warn")

        self.window.powershell.run("status-firewall.ps1", None, on_result)


PAGE_CLASS = DashboardPage
