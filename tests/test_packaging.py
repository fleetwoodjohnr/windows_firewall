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
    @pytest.mark.parametrize("name", ["win-harden.py", "win-harden-broker.py"])
    def test_entry_point_exists(self, name):
        assert (ROOT / name).exists()

    def test_the_gui_entry_point_starts_the_gui(self):
        assert "from win_harden.main import main" in (ROOT / "win-harden.py").read_text()

    def test_the_broker_entry_point_starts_the_broker(self):
        assert "from broker.broker import main" in (ROOT / "win-harden-broker.py").read_text()


class TestBuildScript:
    def test_builds_both_executables(self):
        assert "--name 'win-harden'" in BUILD
        assert "--name 'win-harden-broker'" in BUILD

    def test_each_executable_gets_its_own_manifest(self):
        assert r"--manifest 'installer\app.manifest'" in BUILD
        assert r"--manifest 'installer\broker.manifest'" in BUILD

    def test_the_powershell_scripts_are_bundled(self):
        """The app can read state without them but cannot change anything, so a
        build that omits them produces a plausible-looking, inert app."""
        assert r"'--add-data', \"scripts\ps;scripts\ps\"" in BUILD or \
               "scripts\\ps;scripts\\ps" in BUILD

    def test_the_build_verifies_the_scripts_landed(self):
        assert "set-toggle.ps1" in BUILD, "the build does not check that the scripts were bundled"

    def test_the_broker_does_not_bundle_qt(self):
        """The broker is a transport loop; shipping a GUI toolkit inside the
        elevated process is pure attack surface."""
        assert "--exclude-module PySide6" in BUILD

    def test_the_broker_ends_up_beside_the_gui(self):
        # broker_path() in backend/broker_client.py looks for it there.
        assert "Copy-Item 'dist\\win-harden-broker\\*' 'dist\\win-harden\\'" in BUILD


class TestBootstrap:
    def test_installs_every_runtime_dependency(self):
        for package in ("PySide6", "pywin32", "pyinstaller"):
            assert package in BOOTSTRAP, f"{package} is never installed"

    def test_runs_pywin32_postinstall(self):
        """pywin32 ships DLLs that need registering; without this the named pipe
        code fails at runtime with an import error."""
        assert "pywin32_postinstall" in BOOTSTRAP

    def test_refuses_to_build_from_a_failing_tree(self):
        assert "pytest" in BOOTSTRAP
        assert "Not building an installer from a failing tree" in BOOTSTRAP

    def test_explains_itself_when_winget_is_missing(self):
        assert "winget is not available" in BOOTSTRAP
        assert "python.org/downloads" in BOOTSTRAP


class TestInstaller:
    def test_reverts_before_removing_files(self):
        """The broker doing the reverting is one of the files being removed, so
        order is load-bearing."""
        assert "[UninstallRun]" in ISS
        assert "--revert-all" in ISS
        run_at = ISS.index("[UninstallRun]")
        delete_at = ISS.index("[UninstallDelete]")
        assert run_at < delete_at

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
