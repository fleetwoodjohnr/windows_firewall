"""The packaging, checked from Python.

None of this can be *run* off Windows, but most of the ways it breaks are
things one file saying something another file contradicts -- a manifest with the
wrong execution level, a build script bundling a path that moved, an installer
referencing a file nobody produces. Those are all checkable here, and they are
the failures that would otherwise surface only after a full build on the
Windows box.
"""

import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).resolve().parent.parent

BUILD = (ROOT / "scripts" / "build.ps1").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
ISS = (ROOT / "installer" / "win-harden.iss").read_text(encoding="utf-8")
EXTRAS = (ROOT / "scripts" / "extras.ps1").read_text(encoding="utf-8")
SCAN = (ROOT / "scanner" / "ps" / "operation.ps1").read_text(encoding="utf-8")

TRUST_NS = "urn:schemas-microsoft-com:asm.v3"


def manifest_level(name):
    tree = ElementTree.parse(ROOT / "installer" / name)
    element = tree.find(f".//{{{TRUST_NS}}}requestedExecutionLevel")
    assert element is not None, f"{name} declares no execution level"
    return element.get("level")


class TestManifests:
    """The two manifests are the elevation design. If they are wrong, the whole
    unprivileged-GUI-plus-broker arrangement quietly collapses into either a
    fully elevated app or one that can change nothing."""

    def test_the_gui_never_asks_for_administrator(self):
        assert manifest_level("app.manifest") == "asInvoker", (
            "the GUI must run unelevated; a requireAdministrator here would undo "
            "the entire reason the broker exists")

    def test_the_broker_requires_administrator(self):
        assert manifest_level("broker.manifest") == "requireAdministrator"

    def test_both_are_well_formed_xml(self):
        for name in ("app.manifest", "broker.manifest"):
            ElementTree.parse(ROOT / "installer" / name)

    def test_the_gui_is_dpi_aware(self):
        text = (ROOT / "installer" / "app.manifest").read_text(encoding="utf-8")
        assert "permonitorv2" in text, "a blurry app on a HiDPI laptop looks broken"


class TestEntryPoints:
    @pytest.mark.parametrize("name", ["win-harden.py", "win-harden-broker.py", "win-harden-scanner.py"])
    def test_entry_point_exists(self, name):
        assert (ROOT / name).exists()

    def test_the_gui_entry_point_starts_the_gui(self):
        assert "from win_harden.main import main" in (ROOT / "win-harden.py").read_text()

    def test_the_broker_entry_point_starts_the_broker(self):
        assert "from broker.broker import main" in (ROOT / "win-harden-broker.py").read_text()


def packaged_objects():
    records = []
    class Node:
        def __init__(self, kind, args, kwargs):
            self.kind, self.args, self.kwargs = kind, args, kwargs
            self.pure, self.scripts, self.binaries, self.datas = [], [], [], []
    def factory(kind):
        def make(*args, **kwargs):
            node = Node(kind, args, kwargs)
            records.append(node)
            return node
        return make
    scope = {name: factory(name) for name in ('Analysis', 'PYZ', 'EXE', 'COLLECT')}
    scope['SPECPATH'] = str(ROOT / 'installer')
    spec = ROOT / 'installer' / 'win-harden.spec'
    exec(compile(spec.read_text(), str(spec), 'exec'), scope)
    return records


class TestBuildScript:
    def test_shared_bundle_has_three_executables(self):
        records = packaged_objects()
        exes = [n for n in records if n.kind == 'EXE']
        assert {e.kwargs['name'] for e in exes} == {'win-harden', 'win-harden-broker', 'win-harden-scanner'}
        collect = [n for n in records if n.kind == 'COLLECT']
        assert len(collect) == 1
        assert all(e in collect[0].args for e in exes)
        for exe in exes:
            manifest = Path(exe.kwargs['manifest']).name
            assert manifest_level(manifest) == ('requireAdministrator' if exe.kwargs['name'].endswith('broker') else 'asInvoker')

    def test_privileged_bundles_exclude_qt_and_all_include_actions(self):
        for node in packaged_objects():
            if node.kind != 'Analysis':
                continue
            assert 'broker.actions.defender' in node.kwargs['hiddenimports']
            for source, dest in node.kwargs['datas']:
                assert Path(source).exists()
            assert any(dest == 'scanner/ps' for _, dest in node.kwargs['datas'])
            if Path(node.args[0][0]).name != 'win-harden.py':
                assert 'PySide6' in node.kwargs['excludes']

    def test_build_runs_frozen_validation(self):
        assert 'verify-package.py' in BUILD
        assert 'set-toggle.ps1' in BUILD


class TestBootstrap:
    def test_hosted_runner_is_prepared_without_weakening_download_checks(self):
        preparation = (ROOT / 'scripts' / 'prepare-windows-runner.ps1').read_text()
        workflow = (ROOT / '.github' / 'workflows' / 'windows.yml').read_text()
        assert "RUNNER_ENVIRONMENT -ne 'github-hosted'" in preparation
        assert "GITHUB_ACTIONS -ne 'true'" in preparation
        assert preparation.index('throw') < preparation.index('Set-MpPreference')
        assert '-DisableArchiveScanning $false' in preparation
        assert 'Remove-MpPreference -ExclusionPath $path' in preparation
        assert workflow.index('prepare-windows-runner.ps1') < workflow.index('scripts\\bootstrap.ps1')
        assert 'prepare-windows-runner' not in ISS

    def test_dependencies_pinned_hashed_and_scanned_before_install(self):
        lock = (ROOT / 'requirements-win.lock').read_text().lower()
        for package in ('pyside6', 'pywin32', 'pyinstaller'):
            assert package + '==' in lock
        assert '--require-hashes' in BOOTSTRAP and '--only-binary=:all:' in BOOTSTRAP
        assert BOOTSTRAP.index('Assert-ScannedFile -Path $wheel.FullName') < BOOTSTRAP.index("'pip','install'")
        # pywin32 explicitly forbids postinstall in a virtual environment.
        assert not re.search(r'[-m ]pywin32_postinstall', BOOTSTRAP)

    def test_pinned_vendor_installers(self):
        import json
        manifest = json.loads((ROOT / 'scripts/downloads.json').read_text())
        for name in ('python', 'inno', 'sysmon'):
            assert re.fullmatch(r'[a-fA-F0-9]{64}', manifest[name]['sha256'])
            assert manifest[name]['url'].startswith('https://')
        assert 'Get-VerifiedDownload' in BOOTSTRAP

    def test_refuses_to_build_from_a_failing_tree(self):
        assert 'pytest' in BOOTSTRAP


class TestScanCompletion:
    """Defender writes its scan records after MpCmdRun returns.

    Reading the log once raced that flush, so every download check could fail
    on a machine that had just scanned the file cleanly.
    """

    def test_waits_for_the_completion_event_instead_of_reading_once(self):
        scan = SCAN.index('$output = & $mp @argsList')
        loop_end = SCAN.index('while ((Get-Date) -lt $deadline)')
        window = SCAN[scan:loop_end]
        assert 'Start-Sleep' in window, 'the event log is still read without waiting'
        assert 'AddSeconds(60)' in window, 'the wait must be bounded; nothing times this call out'
        assert 'Get-WinEvent' in window, 'the log must be re-read inside the wait'

    def test_a_second_completed_scan_is_not_a_failure(self):
        # Real-time protection scans the file as it is written, so requiring
        # exactly one completed pair fails on a correctly configured machine.
        assert '@($starts.Keys | Where-Object { $ends.ContainsKey($_) }).Count -ge 1' in SCAN
        assert '$verified = @($starts.Keys | Where-Object { $ends.ContainsKey($_) }).Count -eq 1' not in SCAN

    def test_the_consumed_result_keys_are_still_emitted(self):
        for key in ('exitCode', 'scanCompleted', 'threats', 'excluded', 'error'):
            assert key + '=' in SCAN, f'scanner/engine.py reads {key}'

    def test_diagnostics_never_disclose_scanned_paths(self):
        evidence = SCAN.split('$evidence = @{')[1].split('$active = @{}')[0]
        assert 'Scan Resources' not in evidence
        assert 'attribution' in evidence
        # Command output names the file, so only the caller's own target may appear.
        assert "if ($Operation -eq 'custom')" in evidence
        assert 'Not building an installer from a failing tree' in BOOTSTRAP


class TestInstaller:
    def test_reverts_before_removing_files(self):
        """The broker doing the reverting is one of the files being removed, so
        order is load-bearing."""
        uninstall = ISS.split('function InitializeUninstall(): Boolean;')[1]
        assert uninstall.index('--revert-all') < uninstall.index('--remove')
        assert 'Result := False' in uninstall
        assert 'retained' in uninstall
        assert 'Exit;' in uninstall

    def test_the_broker_supports_the_flag_the_installer_calls(self):
        broker = (ROOT / "broker" / "broker.py").read_text(encoding="utf-8")
        assert '"--revert-all"' in broker
        assert "def revert_all(" in broker

    def test_launches_the_app_unelevated_after_install(self):
        """The installer runs as admin. Launching the app from it without this
        flag would hand the GUI the rights it is designed not to have."""
        assert "runasoriginaluser" in ISS

    def test_requires_windows_11(self):
        assert "MinVersion=10.0.22000" in ISS

    def test_every_extra_is_opt_in(self):
        tasks = re.findall(r'^Name: "(extras[^"]*)".*$', ISS, re.MULTILINE)
        assert tasks, "no extras tasks are declared"
        for line in ISS.splitlines():
            if line.startswith('Name: "extras'):
                assert "Flags: unchecked" in line, f"an extra defaults to on: {line}"

    def test_references_only_files_that_exist(self):
        for match in re.finditer(r'Source: "\.\.\\([^"]+)"', ISS):
            path = match.group(1).replace("\\", "/")
            if "*" in path:
                path = path.split("*")[0].rstrip("/")
                if path.startswith("dist"):
                    continue   # produced by the build, not in the repo
            assert (ROOT / path).exists(), f"the installer references a missing file: {path}"



class TestAllUsersInstall:
    """The machine this ships to has two accounts, and an all-users install is
    not one decision but several: the install root, each shortcut, the sign-in
    entry. Any one of them can be changed to a {user...} constant later and turn
    the whole thing into a one-account install that still looks correct on the
    machine it was installed from."""

    def test_installs_machine_wide(self):
        """These two directives are what make every {auto...} constant below
        resolve to the common area rather than the installing user's."""
        assert "PrivilegesRequired=admin" in ISS
        assert "DefaultDirName={autopf}" in ISS

    @pytest.mark.parametrize("constant", ["{userdesktop}", "{userstartup}",
                                          "{userprograms}", "{userappdata}"])
    def test_no_shortcut_lands_in_one_users_profile(self, constant):
        assert constant not in ISS, (
            f"{constant} installs for the account running setup only; the "
            f"common equivalent covers every account")

    def test_the_download_monitor_starts_for_every_account(self):
        assert "{commonstartup}" in ISS

    def test_uninstall_clears_preferences_from_every_profile(self):
        """Per-account preferences are the one thing not under {app}, so
        removing them means walking the profile list rather than trusting
        whichever account happens to be uninstalling."""
        assert "RemovePerUserData" in ISS
        assert "ProfileImagePath" in ISS
        assert "usPostUninstall" in ISS

    def test_the_wizard_says_who_it_installs_for(self):
        assert "UpdateReadyMemo" in ISS
        assert "All user accounts" in ISS


class TestExtras:
    def test_only_downloads_from_fixed_vendor_urls(self):
        urls = re.findall(r"https://[^\s'\"]+", EXTRAS)
        for url in urls:
            assert url.startswith((
                "https://download.sysinternals.com/",
                "https://raw.githubusercontent.com/SwiftOnSecurity/",
                "https://www.microsoft.com/",
            )), f"unexpected download source: {url}"

    def test_verifies_sysmon_is_signed_before_running_it(self):
        assert "Get-AuthenticodeSignature" in EXTRAS
        assert "Refusing to run it" in EXTRAS

    def test_does_not_apply_the_security_baseline_automatically(self):
        """Three thousand Group Policy settings with no undo is an outage, not
        hardening."""
        assert "does NOT apply it" in EXTRAS
        assert "LGPO.exe /g" in EXTRAS   # shown as an instruction, not executed
        assert not re.search(r"^\s*&\s*.*LGPO", EXTRAS, re.MULTILINE)

    def test_sysmon_can_be_removed(self):
        assert "-RemoveSysmon" in EXTRAS
