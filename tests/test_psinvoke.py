"""What this app is allowed to execute. `-Command` is a shell; these tests exist
to make sure one never appears."""

import pytest

from broker import psinvoke as ps


class TestNeverAShell:
    def test_never_uses_the_command_flag(self):
        for script, spec in ps.SCRIPTS.items():
            params = {name: _sample(name) for name in spec["required"]}
            argv = ps.build_argv(script, params, script_root="/ps")
            assert "-Command" not in argv
            assert "-EncodedCommand" not in argv
            assert "-c" not in argv

    def test_always_runs_a_file(self):
        argv = ps.build_argv("status-defender.ps1", script_root="/ps")
        assert argv[-2] == "-File"
        assert argv[-1].endswith("status-defender.ps1")

    def test_always_disables_the_profile(self):
        # Without -NoProfile an elevated process runs profile scripts we never
        # audited.
        argv = ps.build_argv("status-defender.ps1", script_root="/ps")
        assert "-NoProfile" in argv
        assert "-NonInteractive" in argv

    def test_argv_is_a_list_of_strings(self):
        argv = ps.build_argv("set-defender.ps1",
                             {"Setting": "cloudBlockLevel", "Value": "High"}, script_root="/ps")
        assert isinstance(argv, list)
        assert all(isinstance(part, str) for part in argv)


class TestScriptAllowlist:
    def test_rejects_a_script_not_in_the_list(self):
        for bad in ["evil.ps1", "../evil.ps1", "", "status-defender.ps1 ", "cmd.exe"]:
            with pytest.raises(ps.InvocationError):
                ps.build_argv(bad, script_root="/ps")

    def test_reads_and_writes_are_distinguishable(self):
        assert ps.is_read_only("status-defender.ps1")
        assert ps.is_read_only("list-rule-groups.ps1")
        assert not ps.is_read_only("apply-level.ps1")
        assert not ps.is_read_only("set-toggle.ps1")

    def test_every_read_script_is_named_as_one(self):
        for script in ps.READ_SCRIPTS:
            assert script.startswith(("status-", "list-"))


class TestParameterValues:
    @pytest.mark.parametrize("value", [
        "; Remove-Item C:\\ -Recurse",
        "$(Invoke-Expression 'bad')",
        "block`nStop-Service",
        "block | Out-File",
        "block' ; 'x",
        "../../block",
        "BLOCK",
        "",
    ])
    def test_rejects_an_action_that_is_not_one_of_four(self, value):
        guid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
        with pytest.raises(ps.InvocationError):
            ps.build_argv("set-asr.ps1", {"RuleId": guid, "Action": value}, script_root="/ps")

    def test_toggle_ids_are_a_closed_list_not_a_pattern(self):
        """A toggle that no script implements must be refused here rather than
        reaching a .ps1 that silently has no branch for it."""
        from broker.protocol import TOGGLES
        assert set(TOGGLES) <= set(ps.TOGGLE_IDS)
        for toggle in ps.TOGGLE_IDS:
            ps.build_argv("set-toggle.ps1", {"Toggle": toggle, "State": "off"}, script_root="/ps")
        for bad in ["made-up", "rdp-x", "RDP", ""]:
            with pytest.raises(ps.InvocationError):
                ps.build_argv("set-toggle.ps1", {"Toggle": bad, "State": "off"}, script_root="/ps")

    def test_defender_setting_and_value_are_closed_enums(self):
        ps.build_argv("set-defender.ps1", {"Setting": "cloudBlockLevel", "Value": "HighPlus"},
                      script_root="/ps")
        for setting, value in [("wipeDisk", "High"), ("cloudBlockLevel", "$(bad)"),
                               ("cloudBlockLevel", "High; Stop-Service")]:
            with pytest.raises(ps.InvocationError):
                ps.build_argv("set-defender.ps1", {"Setting": setting, "Value": value},
                              script_root="/ps")

    def test_rejects_a_value_that_looks_like_a_switch(self):
        # PowerShell would bind a leading '-' as the next parameter name.
        with pytest.raises(ps.InvocationError, match="may not begin"):
            ps.build_argv("set-toggle.ps1", {"Toggle": "-Force", "State": "off"}, script_root="/ps")

    def test_rejects_an_undeclared_parameter(self):
        with pytest.raises(ps.InvocationError, match="does not accept"):
            ps.build_argv("set-defender.ps1",
                          {"Setting": "cloudBlockLevel", "Value": "High", "Path": "C:\\"},
                          script_root="/ps")

    def test_rejects_a_missing_required_parameter(self):
        with pytest.raises(ps.InvocationError, match="requires parameter"):
            ps.build_argv("set-defender.ps1", {"Setting": "cloudBlockLevel"}, script_root="/ps")

    def test_rejects_a_bool(self):
        with pytest.raises(ps.InvocationError, match="bool"):
            ps.build_argv("set-toggle.ps1", {"Toggle": "rdp", "State": True}, script_root="/ps")

    @pytest.mark.parametrize("group", [
        "File and Printer Sharing",
        "Remote Desktop",
        "Network Discovery (NB-Name-In)",
        "mDNS",
    ])
    def test_accepts_a_real_rule_group_name(self, group):
        argv = ps.build_argv("set-rule-group.ps1",
                             {"Profile": "Public", "Group": group, "State": "off"},
                             script_root="/ps")
        assert group in argv

    @pytest.mark.parametrize("group", [
        "Group`; Stop-Computer", "$(bad)", 'x" ; y', "a|b", "x;y", "a" * 200,
    ])
    def test_rejects_a_rule_group_shaped_like_powershell(self, group):
        with pytest.raises(ps.InvocationError):
            ps.build_argv("set-rule-group.ps1",
                          {"Profile": "Public", "Group": group, "State": "off"},
                          script_root="/ps")

    def test_every_declared_parameter_has_a_pattern(self):
        for script, spec in ps.SCRIPTS.items():
            for name in spec["required"] + spec["optional"]:
                assert name in ps.PARAM_PATTERNS, f"{script}:{name} has no value pattern"


def _sample(name):
    return {
        "Level": "off", "Family": "dns", "Provider": "quad9", "Profile": "Public",
        "Action": "block", "State": "off", "Category": "Public", "Toggle": "rdp",
        "RuleId": "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "InterfaceIndex": "3",
        "Group": "Remote Desktop", "Setting": "cloudBlockLevel", "Value": "High",
        "Mitigation": "dep", "Resource": "firewall", "Data": "W10=",
        "ServiceName": "WinRM", "StartupType": "Manual",
    }[name]
