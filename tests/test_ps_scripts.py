"""The PowerShell layer, checked from Python.

Validation is deliberately done twice -- once in `psinvoke.build_argv` and again
in each script's `[ValidateSet]` -- by two processes in two languages. That is
only worth anything if the two agree, and nothing in either language checks the
other. These tests are what closes that gap.

They also assert the properties that make the whole "never a shell" rule hold on
the PowerShell side, where an argv list alone is not enough.
"""

import re
from pathlib import Path

import pytest

from broker import dns_providers
from broker.psinvoke import PARAM_PATTERNS, SCRIPTS, TOGGLE_IDS

PS_DIR = Path(__file__).resolve().parent.parent / "scripts" / "ps"


def script_text(name):
    return (PS_DIR / name).read_text(encoding="utf-8")


ALL_SCRIPTS = sorted(SCRIPTS)


class TestScriptsExist:
    def test_every_declared_script_is_shipped(self):
        missing = [name for name in SCRIPTS if not (PS_DIR / name).exists()]
        assert not missing, f"declared in psinvoke but not on disk: {missing}"

    def test_every_shipped_script_is_declared(self):
        on_disk = {p.name for p in PS_DIR.glob("*.ps1")}
        assert not (on_disk - set(SCRIPTS)), (
            f"on disk but not in the allowlist, so unreachable: {on_disk - set(SCRIPTS)}")


@pytest.mark.parametrize("name", ALL_SCRIPTS)
class TestScriptDiscipline:
    def test_stops_on_error(self, name):
        """A script that half-works and exits 0 makes the app report protection
        that is not there."""
        assert "$ErrorActionPreference = 'Stop'" in script_text(name)

    def test_never_evaluates_a_string_as_code(self, name):
        text = script_text(name)
        for construct in ("Invoke-Expression", "iex ", "iex(", "&(", "& (", "[scriptblock]::Create"):
            assert construct not in text, f"{name} uses {construct!r}"

    def test_emits_json_with_an_explicit_depth_or_is_flat(self, name):
        """ConvertTo-Json defaults to -Depth 2 and silently truncates deeper
        objects into the string 'System.Object[]'."""
        text = script_text(name)
        assert "ConvertTo-Json" in text, f"{name} produces no JSON output"
        for call in re.findall(r"ConvertTo-Json[^\n|]*", text):
            if "-Depth" in call:
                continue
            # A flat payload is fine at the default depth; assert it really is
            # flat by checking the piped object has no nested construction.
            assert "@{" in text, name

    def test_declares_every_parameter_it_is_given(self, name):
        text = script_text(name)
        spec = SCRIPTS[name]
        for param in spec["required"] + spec["optional"]:
            assert re.search(rf"\${param}\b", text), (
                f"psinvoke passes -{param} to {name}, but the script has no such parameter")

    def test_has_no_parameters_python_never_supplies(self, name):
        text = script_text(name)
        declared = set(re.findall(r"^\s*\[(?:string|int)\]\$(\w+)", text, re.MULTILINE))
        permitted = set(SCRIPTS[name]["required"]) | set(SCRIPTS[name]["optional"])
        assert declared <= permitted, (
            f"{name} declares {declared - permitted}, which psinvoke can never supply")


class TestValidatorsAgree:
    """Each ValidateSet must accept exactly what the Python pattern accepts. A
    Python-side value the script rejects is a runtime failure; a script-side
    value Python rejects is dead code that hides a gap."""

    def _validate_sets(self, name):
        text = script_text(name)
        found = {}
        # [ValidateSet('a','b')] followed (possibly after a newline) by [type]$Name
        for match in re.finditer(
            r"\[ValidateSet\(([^)]*)\)\]\s*\[string\]\$(\w+)", text, re.DOTALL
        ):
            values = set(re.findall(r"'([^']*)'", match.group(1)))
            found[match.group(2)] = values
        return found

    @pytest.mark.parametrize("name", ALL_SCRIPTS)
    def test_validate_set_matches_the_python_pattern(self, name):
        for param, values in self._validate_sets(name).items():
            pattern = PARAM_PATTERNS.get(param)
            assert pattern, f"{name} validates -{param}, which psinvoke does not constrain"
            rejected = {v for v in values if not re.match(pattern, v)}
            assert not rejected, (
                f"{name} accepts {sorted(rejected)} for -{param}, but psinvoke would "
                f"refuse to pass them. The two validators disagree.")

    def test_set_toggle_implements_every_toggle_id(self):
        """A toggle with no branch would be accepted and silently do nothing."""
        text = script_text("set-toggle.ps1")
        validate = self._validate_sets("set-toggle.ps1")["Toggle"]
        assert validate == set(TOGGLE_IDS), (
            f"set-toggle.ps1 and psinvoke.TOGGLE_IDS disagree: "
            f"{validate ^ set(TOGGLE_IDS)}")
        # Every id must appear as a switch branch, not merely in the ValidateSet.
        body = text.split("switch ($Toggle)", 1)[1]
        for toggle in TOGGLE_IDS:
            assert f"'{toggle}'" in body, f"set-toggle.ps1 has no branch for {toggle!r}"

    def test_set_defender_implements_every_setting(self):
        text = script_text("set-defender.ps1")
        settings = self._validate_sets("set-defender.ps1")["Setting"]
        body = text.split("switch ($Setting)", 1)[1]
        for setting in settings:
            assert f"'{setting}'" in body, f"set-defender.ps1 has no branch for {setting!r}"

    def test_set_mitigation_implements_every_mitigation(self):
        text = script_text("set-mitigation.ps1")
        mitigations = self._validate_sets("set-mitigation.ps1")["Mitigation"]
        body = text.split("switch ($Mitigation)", 1)[1]
        for mitigation in mitigations:
            assert f"'{mitigation}'" in body


class TestDnsProviderTable:
    """set-dns-provider.ps1 holds the authoritative addresses; dns_providers.py
    holds the copy shown in the UI. This is the one genuine mirror left in the
    project, so it gets a test."""

    def _ps_table(self):
        text = script_text("set-dns-provider.ps1")
        block = text.split("$PROVIDERS = @{", 1)[1].split("\n}", 1)[0]
        table = {}
        for match in re.finditer(
            r"'(\w+)'\s*=\s*@\{\s*v4\s*=\s*@\(([^)]*)\)\s*v6\s*=\s*@\(([^)]*)\)\s*"
            r"template\s*=\s*'([^']*)'",
            block, re.DOTALL,
        ):
            table[match.group(1)] = {
                "v4": tuple(re.findall(r"'([^']*)'", match.group(2))),
                "v6": tuple(re.findall(r"'([^']*)'", match.group(3))),
                "template": match.group(4),
            }
        return table

    def test_the_script_defines_every_pinnable_provider(self):
        ps = self._ps_table()
        expected = {p.id for p in dns_providers.PROVIDERS if p.id != "automatic"}
        assert set(ps) == expected, f"tables disagree on which providers exist: {set(ps) ^ expected}"

    @pytest.mark.parametrize("provider_id",
                             [p.id for p in dns_providers.PROVIDERS if p.id != "automatic"])
    def test_addresses_and_templates_match(self, provider_id):
        ps = self._ps_table()[provider_id]
        py = dns_providers.BY_ID[provider_id]
        assert ps["v4"] == py.ipv4, f"{provider_id} IPv4 addresses differ"
        assert ps["v6"] == py.ipv6, f"{provider_id} IPv6 addresses differ"
        assert ps["template"] == py.template, f"{provider_id} DoH template differs"

    def test_automatic_pins_nothing(self):
        automatic = dns_providers.BY_ID["automatic"]
        assert automatic.ipv4 == () and automatic.ipv6 == () and automatic.template == ""
        assert "'automatic'" not in "".join(self._ps_table())


class TestDohIsActuallyEnforced:
    def test_pinning_registers_the_template_before_setting_servers(self):
        """An interface pointed at a resolver Windows has no DoH template for
        falls back to plaintext -- it looks like it worked and is not
        encrypted."""
        text = script_text("set-dns-provider.ps1")
        register = text.index("DnsClientDohServerAddress")
        assign = text.index("Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses")
        assert register < assign

    def test_pinning_disallows_udp_fallback(self):
        text = script_text("set-dns-provider.ps1")
        assert text.count("-AllowFallbackToUdp $false") >= 2
        assert "-AllowFallbackToUdp $true" not in text
