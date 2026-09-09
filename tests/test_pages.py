"""The UI layer, exercised headless.

Qt runs fine on any platform; only the Windows backends do not. So the pages,
the widgets and -- most importantly -- the non-optimistic state rule can all be
tested here, with the broker and PowerShell replaced by fakes.

The rule under test throughout:

    A control's visible position reflects the system, never the request.

It is the property the whole app depends on for honesty. On Windows it matters
more than it did on Fedora, because more changes can be accepted and then
refused -- Tamper Protection, a domain policy, a licence tier -- and a control
that moved on click would report protection the machine does not have.
"""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from win_harden.data.levels import FAMILIES, get_family  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def auto_confirm(monkeypatch):
    """Answer every confirmation dialog with the confirm button.

    Confirmations are non-modal callbacks, so a test cannot click one. Replacing
    the dialog with an immediate yes is what lets the paths *behind* a
    confirmation be tested at all.
    """
    def immediate(parent, heading, body, label, on_confirm, on_cancel=None, destructive=True):
        on_confirm()
        return None

    for module in ("win_harden.widgets.level_selector", "win_harden.pages.dashboard",
                   "win_harden.pages.firewall"):
        monkeypatch.setattr(module + ".confirm", immediate, raising=False)
    return immediate


class FakeBroker:
    """Records calls; answers with whatever the test set up."""

    def __init__(self, status=None, fail_with=None):
        self.calls = []
        self._status = status or {"recorded": {"families": {}}, "live": {}}
        self.fail_with = fail_with

    def status(self, callback):
        self.calls.append(("status", ()))
        callback(self._status, None)

    def _respond(self, name, args, callback, result=None):
        self.calls.append((name, args))
        if self.fail_with is not None:
            callback(None, self.fail_with)
        else:
            callback(result if result is not None else {}, None)

    def apply_level(self, family, level, callback):
        self._respond("apply", (family, level), callback,
                      {"family": family, "level": level, "notes": {}})

    def revert(self, family, callback):
        self._respond("revert", (family,), callback)

    def set_asr_rule(self, rule_id, action, callback):
        self._respond("set-asr", (rule_id, action), callback)

    def set_toggle(self, toggle, enabled, callback):
        self._respond("set-toggle", (toggle, enabled), callback)

    def set_rule_group(self, profile, group, enabled, callback):
        self._respond("set-rule-group", (profile, group, enabled), callback)

    def set_network_category(self, index, category, callback):
        self._respond("set-network-category", (index, category), callback)

    def set_dns_provider(self, provider, index, callback):
        self._respond("set-dns", (provider, index), callback)


class FakePowerShell:
    def __init__(self, results=None, error=None):
        self.calls = []
        self._results = results or {}
        self._error = error

    def run(self, script, params=None, callback=None):
        self.calls.append((script, params))
        if callback is None:
            return
        if self._error is not None:
            callback(None, self._error)
            return
        callback(self._results.get(script, {}), None)


class FakeWindow(QWidget):
    """A real QWidget, because pages pass it as a dialog parent."""

    def __init__(self, broker=None, powershell=None, tmp_path=None):
        super().__init__()
        from win_harden.settings import AppSettings

        self.broker = broker or FakeBroker()
        self.powershell = powershell or FakePowerShell()
        self.settings = AppSettings(str(tmp_path / "s.json")) if tmp_path else AppSettings(
            "/tmp/win-harden-test-settings.json")
        self.nav = None


def build_page(page_id, window):
    module = __import__(f"win_harden.pages.{page_id}", fromlist=[page_id])
    return module.PAGE_CLASS(window)


ALL_PAGES = ("dashboard", "firewall", "networks", "protection", "hardening")


@pytest.mark.parametrize("page_id", ALL_PAGES)
class TestPagesBuild:
    def test_constructs(self, qapp, tmp_path, page_id):
        page = build_page(page_id, FakeWindow(tmp_path=tmp_path))
        assert page is not None

    def test_refreshes_without_error(self, qapp, tmp_path, page_id):
        page = build_page(page_id, FakeWindow(tmp_path=tmp_path))
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    def test_survives_a_backend_that_fails(self, qapp, tmp_path, page_id):
        """A machine the app cannot read must produce an explanation, never a
        crash and never a page that looks like a clean result."""
        from win_harden.backend.errors import BrokerUnavailable

        window = FakeWindow(
            broker=FakeBroker(fail_with=BrokerUnavailable("no broker")),
            powershell=FakePowerShell(error=BrokerUnavailable("no powershell")),
            tmp_path=tmp_path,
        )
        # A failing status must still let the page build and refresh.
        window.broker.status = lambda cb: cb(None, BrokerUnavailable("no broker"))
        page = build_page(page_id, window)
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()
        banner = getattr(page, "banner", None)
        if banner is not None:
            assert banner.showing, f"{page_id} failed silently instead of explaining"


class TestLevelSelector:
    """The signature widget. Its contract is that clicking a notch applies
    nothing until the change lands."""

    def _selector(self, qapp, on_apply):
        from win_harden.widgets.level_selector import LevelSelector

        family = get_family("tls")
        return LevelSelector(family.levels, on_apply, None, "TLS")

    def test_shows_every_level(self, qapp):
        selector = self._selector(qapp, lambda level, done: None)
        assert [b.text() for b in selector._buttons] == ["Off", "Basic", "Balanced", "Strict"]

    def test_starts_at_off(self, qapp):
        selector = self._selector(qapp, lambda level, done: None)
        assert selector.get_active_level().id == "off"

    def test_set_active_level_moves_without_applying(self, qapp):
        applied = []
        selector = self._selector(qapp, lambda level, done: applied.append(level))
        selector.set_active_level("balanced")
        assert selector.get_active_level().id == "balanced"
        assert selector._buttons[2].isChecked()
        assert applied == [], "syncing to system state must never apply anything"

    def test_an_unknown_level_falls_back_to_off(self, qapp):
        selector = self._selector(qapp, lambda level, done: None)
        selector.set_active_level("nonsense")
        assert selector.get_active_level().id == "off"

    def test_a_failed_apply_leaves_the_control_where_the_system_is(self, qapp, auto_confirm):
        """The core non-optimistic guarantee: a refused change must never move
        the control, or the app reports protection the machine does not have."""
        selector = self._selector(qapp, lambda level, done: done(False))
        selector.set_active_level("basic")
        selector._requested(3)                    # user clicks Strict, confirms
        assert selector.get_active_level().id == "basic", (
            "the control moved to a level the system never reached")
        assert selector._buttons[1].isChecked()

    def test_a_successful_apply_moves_the_control(self, qapp, auto_confirm):
        applied = []

        def on_apply(level, done):
            applied.append(level.id)
            done(True)

        selector = self._selector(qapp, on_apply)
        selector.set_active_level("off")
        selector._requested(2)                    # user clicks Balanced, confirms
        assert applied == ["balanced"]
        assert selector.get_active_level().id == "balanced"

    def test_cancelling_applies_nothing(self, qapp, monkeypatch):
        applied = []
        monkeypatch.setattr(
            "win_harden.widgets.level_selector.confirm",
            lambda parent, h, b, l, on_confirm, on_cancel=None, destructive=True: (
                on_cancel() if on_cancel else None))
        selector = self._selector(qapp, lambda level, done: applied.append(level.id))
        selector.set_active_level("basic")
        selector._requested(3)
        assert applied == []
        assert selector.get_active_level().id == "basic"

    def test_the_applied_level_drives_the_colour_not_the_preview(self, qapp):
        selector = self._selector(qapp, lambda level, done: None)
        selector.set_active_level("basic")
        applied = [b for b in selector._buttons if b.property("applied")]
        assert len(applied) == 1
        assert applied[0].text() == "Basic"
        assert applied[0].property("level") == "basic"


class TestToggleRow:
    def _row(self, qapp, on_toggle):
        from win_harden.data.rule_groups import describe
        from win_harden.widgets.toggle_row import ToggleRow

        return ToggleRow("Remote Desktop", describe("Remote Desktop"), False,
                         on_toggle, lambda *a: None)

    def test_a_failed_toggle_snaps_back(self, qapp):
        row = self._row(qapp, lambda key, requested, done: done(False))
        row._on_clicked(True)
        assert row._switch.isChecked() is False

    def test_a_successful_toggle_moves(self, qapp):
        row = self._row(qapp, lambda key, requested, done: done(True))
        row._on_clicked(True)
        assert row._switch.isChecked() is True

    def test_set_enabled_state_does_not_fire_a_write(self, qapp):
        calls = []
        row = self._row(qapp, lambda key, requested, done: calls.append(key))
        row.set_enabled_state(True)
        row.set_enabled_state(False)
        assert calls == []


class TestProtectionPage:
    def test_lists_every_desktop_asr_rule(self, qapp, tmp_path):
        from broker.asr_catalog import desktop_rules

        page = build_page("protection", FakeWindow(tmp_path=tmp_path))
        assert len(page.rule_rows) == len(desktop_rules())

    def test_warn_is_not_offered_for_rules_that_lack_it(self, qapp, tmp_path):
        from broker.asr_catalog import BY_GUID

        page = build_page("protection", FakeWindow(tmp_path=tmp_path))
        for guid, row in page.rule_rows.items():
            actions = {row.combo.itemData(i) for i in range(row.combo.count())}
            if BY_GUID[guid].supports_warn:
                assert "warn" in actions
            else:
                assert "warn" not in actions, f"{BY_GUID[guid].name} has no Warn mode"

    def test_tamper_protection_raises_a_banner(self, qapp, tmp_path):
        status = {"recorded": {"families": {}}, "live": {"defender": {}, "exploit": {}},
                  "tamperProtected": True}
        page = build_page("protection", FakeWindow(FakeBroker(status), tmp_path=tmp_path))
        page.refresh()
        assert page.banner.showing


class TestDashboard:
    def test_an_unreadable_machine_is_not_reported_as_clean(self, qapp, tmp_path):
        """The failure mode that would matter most: a dashboard that shows no
        problems because it could not check for any."""
        page = build_page("dashboard", FakeWindow(FakeBroker({"recorded": {}, "live": {}}),
                                                  tmp_path=tmp_path))
        page.refresh()
        text = page.findings_placeholder.text()
        assert "not a clean bill of health" in text or "could not be read" in text

    def test_a_genuinely_clean_machine_says_so(self, qapp, tmp_path):
        clean = {
            "recorded": {"families": {f.id: {"level": "strict"} for f in FAMILIES}},
            "live": {
                "defender": {"realtimeProtection": True, "signatureAgeDays": 0,
                             "asrRules": {"x": "block"}},
                "exploit": {"bitlocker": [{"protectionOn": True, "recoveryKeySaved": True}]},
                "exposure": {"features": [], "rdpDenied": 1, "llmnrDisabled": 0},
                "credential": {"lsaProtection": 1, "wdigestPlaintext": 0},
                "dns": {"interfaces": [{"index": 1, "dohEnabled": True}]},
                "tls": {"protocols": {"TLS 1.0": {"client": False}}},
            },
        }
        page = build_page("dashboard", FakeWindow(FakeBroker(clean), tmp_path=tmp_path))
        page.refresh()
        assert "Nothing to flag" in page.findings_placeholder.text()

    def test_panic_mode_does_not_engage_without_confirmation(self, qapp, tmp_path, monkeypatch):
        cancelled = []
        monkeypatch.setattr(
            "win_harden.pages.dashboard.confirm",
            lambda parent, h, b, l, on_confirm, on_cancel=None, destructive=True: cancelled.append(1))
        broker = FakeBroker()
        page = build_page("dashboard", FakeWindow(broker, tmp_path=tmp_path))
        page._on_panic_clicked(True)
        assert cancelled, "blocking all traffic was not confirmed first"
        assert not any(name == "set-toggle" for name, _args in broker.calls)
        assert page.panic_switch.isChecked() is False

    def test_panic_mode_engages_once_confirmed(self, qapp, tmp_path, auto_confirm):
        broker = FakeBroker()
        page = build_page("dashboard", FakeWindow(broker, tmp_path=tmp_path))
        page._on_panic_clicked(True)
        assert ("set-toggle", ("panic-mode", True)) in broker.calls

    def test_turning_panic_mode_off_needs_no_confirmation(self, qapp, tmp_path):
        broker = FakeBroker()
        page = build_page("dashboard", FakeWindow(broker, tmp_path=tmp_path))
        page._on_panic_clicked(False)
        assert ("set-toggle", ("panic-mode", False)) in broker.calls


class TestFirewallPage:
    def test_renders_reported_groups(self, qapp, tmp_path):
        results = {"list-rule-groups.ps1": {"groups": [
            {"name": "Remote Desktop", "total": 4, "enabled": 4, "state": "on"},
            {"name": "File and Printer Sharing", "total": 6, "enabled": 2, "state": "partial"},
        ]}}
        page = build_page("firewall", FakeWindow(powershell=FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        assert set(page._rows) == {"Remote Desktop", "File and Printer Sharing"}

    def test_a_partial_group_says_so_rather_than_rounding(self, qapp, tmp_path):
        results = {"list-rule-groups.ps1": {"groups": [
            {"name": "File and Printer Sharing", "total": 6, "enabled": 2, "state": "partial"},
        ]}}
        page = build_page("firewall", FakeWindow(powershell=FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        row = page._rows["File and Printer Sharing"]
        assert "Partly on" in row.info.summary
        assert row._switch.isChecked() is False

    def test_essential_groups_are_confirmed_before_being_switched_off(
            self, qapp, tmp_path, monkeypatch):
        asked = []
        monkeypatch.setattr(
            "win_harden.pages.firewall.confirm",
            lambda parent, h, b, l, on_confirm, on_cancel=None, destructive=True: asked.append(h))
        broker = FakeBroker()
        results = {"list-rule-groups.ps1": {"groups": [
            {"name": "Core Networking", "total": 10, "enabled": 10, "state": "on"},
        ]}}
        page = build_page("firewall", FakeWindow(broker, FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        page._on_toggle("Core Networking", False, lambda *a: None)
        assert asked, "an essential group was disabled without confirmation"
        assert not any(n == "set-rule-group" for n, _a in broker.calls)

    def test_a_normal_group_needs_no_confirmation(self, qapp, tmp_path):
        broker = FakeBroker()
        results = {"list-rule-groups.ps1": {"groups": [
            {"name": "Remote Desktop", "total": 4, "enabled": 4, "state": "on"},
        ]}}
        page = build_page("firewall", FakeWindow(broker, FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        page._on_toggle("Remote Desktop", False, lambda *a: None)
        assert ("set-rule-group", ("Public", "Remote Desktop", False)) in broker.calls


class TestNetworksPage:
    def test_domain_networks_cannot_be_changed(self, qapp, tmp_path):
        results = {"status-network.ps1": {"interfaces": [
            {"index": 3, "name": "Ethernet", "category": "DomainAuthenticated", "dnsServers": []},
        ]}}
        page = build_page("networks", FakeWindow(powershell=FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        row = page._rows[3]
        assert row.category_combo.isEnabled() is False

    def test_an_unencrypted_adapter_is_called_out(self, qapp, tmp_path):
        results = {"status-network.ps1": {"interfaces": [
            {"index": 5, "name": "Wi-Fi", "category": "Public",
             "dnsServers": ["192.168.1.1"], "dohEnabled": False},
        ]}}
        page = build_page("networks", FakeWindow(powershell=FakePowerShell(results),
                                                 tmp_path=tmp_path))
        page.refresh()
        assert "NOT encrypted" in page._rows[5].detail.text()
