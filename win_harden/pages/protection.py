"""Protection: Microsoft Defender, ASR rules, exploit mitigations and ransomware.

Two level selectors plus the per-rule ASR list. The rule list is the part that
does not exist on the Fedora side at all, and it is here because ASR is the
highest-value anti-malware control Windows has and because a level alone cannot
express "everything except this one rule that breaks my VPN client".

Tamper Protection gets a banner rather than a silent failure. That decision is
made in `guards.py`, which refuses the change; this page's job is to explain it
and say what to do, in the same shape as the Fedora app's "the privileged helper
isn't installed" banner (pages/hardening.py:101-137).
"""

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from broker.asr_catalog import ACTION_TO_MP, desktop_rules

from ..widgets.page import Group, KeyValueRow, unknown_label
from ._levels_page import LevelFamilyPage

ACTION_LABELS = (("off", "Off"), ("audit", "Audit"), ("warn", "Warn"), ("block", "Block"))

TAMPER_HELP = (
    "Windows Security → Virus & threat protection → Manage settings → Tamper Protection.\n\n"
    "Turn it off, apply the level you want here, then switch it back on. No application is "
    "allowed to turn it off for you, which is exactly what makes it useful."
)


class AsrRuleRow(QWidget):
    """One ASR rule: name, explanation, and a four-way action picker.

    The picker offers Warn only for rules that support it. Two rules genuinely
    do not, and offering a fourth option that silently becomes something else
    would misreport what the machine is doing.
    """

    def __init__(self, rule, on_change, parent=None):
        super().__init__(parent)
        self.rule = rule
        self._on_change = on_change
        self._syncing = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(12)

        title = QLabel(rule.name, self)
        title.setObjectName("rowTitle")
        title.setWordWrap(True)
        top.addWidget(title, 1)

        self.combo = QComboBox(self)
        for action_id, label in ACTION_LABELS:
            if action_id == "warn" and not rule.supports_warn:
                continue
            self.combo.addItem(label, action_id)
        self.combo.setFixedWidth(110)
        self.combo.currentIndexChanged.connect(self._on_selected)
        top.addWidget(self.combo, 0)
        layout.addLayout(top)

        caveats = []
        if not rule.supports_warn:
            caveats.append("No Warn mode: Microsoft supports only Off, Audit and Block here.")
        if rule.needs_cloud:
            caveats.append("Does nothing unless cloud-delivered protection is on.")
        if rule.incompatibilities:
            caveats.append("Known to conflict with: " + ", ".join(rule.incompatibilities) + ".")

        body = QLabel(
            f"{rule.summary}\n\n{rule.detail}\n\nWhat this might break: {rule.breaks}"
            + ("\n\n" + " ".join(caveats) if caveats else ""),
            self,
        )
        body.setObjectName("rowDetail")
        body.setWordWrap(True)
        layout.addWidget(body)

    def set_action(self, action_id):
        """Move the picker to what Defender reports, without applying."""
        self._syncing = True
        index = self.combo.findData(action_id)
        self.combo.setCurrentIndex(index if index >= 0 else 0)
        self._syncing = False

    def _on_selected(self, _index):
        if self._syncing:
            return
        wanted = self.combo.currentData()
        previous = self._current_from_system
        # Same non-optimistic rule as everywhere else: put it back and let the
        # result move it.
        self.set_action(previous)

        def done(ok, action):
            if ok:
                self._current_from_system = action
                self.set_action(action)

        self._on_change(self.rule, wanted, done)

    _current_from_system = "off"

    def remember(self, action_id):
        self._current_from_system = action_id


class ProtectionPage(LevelFamilyPage):
    FAMILIES = ("defender", "exploit")
    TITLE = "Protection"
    SUBTITLE = (
        "Microsoft Defender, the Attack Surface Reduction rules that block how malware behaves, "
        "and the memory protections that make exploits harder to land."
    )

    def build_extras(self):
        self._build_defender_status()
        self._build_rule_list()

    def _build_defender_status(self):
        group = Group("Defender status", "Read from the machine, not from what this app recorded.", self)
        self.status_rows = {
            "realtime": KeyValueRow("Real-time protection", "—"),
            "tamper": KeyValueRow("Tamper Protection", "—"),
            "signatures": KeyValueRow("Signature age", "—"),
            "cfa": KeyValueRow("Controlled Folder Access", "—"),
            "bitlocker": KeyValueRow("BitLocker", "—"),
        }
        for row in self.status_rows.values():
            group.add(row)
        self.add(group)

    def _build_rule_list(self):
        group = Group(
            "Attack Surface Reduction rules",
            "Each rule individually. A level sets all of these together; change one here when a "
            "level is right except for a single rule.",
            self,
        )
        self.rule_rows = {}
        for rule in desktop_rules():
            row = AsrRuleRow(rule, self._on_rule_change, group)
            self.rule_rows[rule.guid] = row
            group.add(row)
        self.add(group)

    # -- per-rule changes -----------------------------------------------------

    def _on_rule_change(self, rule, action, done):
        def on_result(_result, error):
            if error is not None:
                self.banner.show_message(
                    f"'{rule.name}' could not be set to {action}", str(error), tone="error")
                done(False, None)
                return
            self.banner.show_message(
                f"'{rule.name}' is now {action}",
                f"Applied as {ACTION_TO_MP[action]}.", tone="ok")
            done(True, action)

        self.broker.set_asr_rule(rule.guid, action, on_result)

    # -- status ---------------------------------------------------------------

    def on_status(self, status):
        live = status.get("live") or {}
        defender = live.get("defender") or {}
        exploit = live.get("exploit") or {}

        tampered = status.get("tamperProtected")
        if tampered:
            self.banner.show_message(
                "Tamper Protection is on, so Defender settings cannot be changed",
                TAMPER_HELP, tone="warning")

        self.status_rows["realtime"].set_value(
            unknown_label(defender.get("realtimeProtection")),
            "ok" if defender.get("realtimeProtection") else "bad")
        self.status_rows["tamper"].set_value(
            unknown_label(tampered, yes="On (blocks changes)", no="Off"),
            "warn" if tampered else "ok")

        age = defender.get("signatureAgeDays")
        self.status_rows["signatures"].set_value(
            "Not reported" if age is None else (f"{age} days old" if age else "Up to date"),
            "ok" if (age is not None and age <= 2) else "warn")

        cfa = exploit.get("controlledFolderAccess")
        self.status_rows["cfa"].set_value(
            cfa or "Not reported", "ok" if cfa == "Enabled" else "warn")

        volumes = exploit.get("bitlocker") or []
        if not volumes:
            self.status_rows["bitlocker"].set_value("Not available", "warn")
        else:
            protected = [v for v in volumes if v.get("protectionOn")]
            unsaved = [v for v in protected if not v.get("recoveryKeySaved")]
            if not protected:
                self.status_rows["bitlocker"].set_value("Off on every drive", "bad")
            elif unsaved:
                self.status_rows["bitlocker"].set_value(
                    f"On, but {len(unsaved)} drive(s) have no saved recovery key", "bad")
            else:
                self.status_rows["bitlocker"].set_value(
                    f"On, recovery key saved ({len(protected)} drive(s))", "ok")

        applied = defender.get("asrRules") or {}
        for guid, row in self.rule_rows.items():
            action = applied.get(guid, "off")
            row.remember(action)
            row.set_action(action)


PAGE_CLASS = ProtectionPage
