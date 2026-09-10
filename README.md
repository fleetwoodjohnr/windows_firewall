# Windows Firewall & Hardening

A Windows counterpart of [firewall-gui for Fedora](https://github.com/fleetwoodjohnr/fedora_firewall_gui), using Windows Firewall and Microsoft Defender. Targets **Windows 11, Intel/AMD x64**. ARM64 is not supported by this installer.

The pages are Dashboard, Firewall Rules, Networks, Protection, Hardening, **Virus Scan**, and **Updates**. The GUI runs without administrator rights. Security changes use a separate helper through UAC; long antivirus operations run in a Windows service.

## Build and install

On Windows 11 x64, open **64-bit Windows PowerShell as Administrator** in this checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
```

If the exact pinned Python 3.13 x64 release is already installed, pass its executable explicitly to avoid the Python installer's maintenance mode:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -BuildPython "C:\path\to\python.exe"
```

The bootstrap automatically downloads the pinned Python runtime, Qt, pywin32, PyInstaller, test dependencies, and Inno Setup. Downloads use HTTPS and SHA-256 checks; vendor executables also require the expected Authenticode publisher. Microsoft Defender scans downloaded installers and dependency wheels before they are installed. Verification failure stops the build. Defender must be active with archive scanning enabled; restricted corporate policies may require administrator assistance. The script does not disable antivirus protection or create antivirus exclusions.

The build runs tests and checks the three frozen executables outside the source directory, then produces:

```text
installer\Output\WinHardenSetup-1.2.1.exe
installer\Output\WinHardenSetup-1.2.1.exe.sha256
```

Run that installer on the target PC. **Python, Qt and pywin32 are bundled:** the installed application does not need a separate Python installation, pip, winget, or a developer environment. Windows 11 supplies PowerShell, Windows Firewall and Defender. The installer installs the scan service and a sign-in shortcut for the tray monitor. Optional Sysmon and definition updates require internet access; Sysmon downloads are hash-checked, signature-checked and scanned. The optional baseline item opens Microsoft's download page for manual review.

### Two user accounts

The install is machine-wide. It goes to `C:\Program Files\win-harden`, and the Start Menu entry, the optional desktop shortcut and the sign-in shortcut for the tray monitor are created for **every** account on the PC, not only the one that ran setup. The wizard states this on its Ready to Install page.

The settings the app applies were never per-account: hardening families write machine-wide registry values under `HKLM`, and firewall profiles, Defender configuration and services are machine state. A change applied from one account is therefore already in force for the other, and the second account's Dashboard reads the same state rather than a separate copy of it. Applying a change always needs Administrator approval; a standard account is asked for an administrator password rather than a simple confirmation.

What stays per-account is preference only: watched download folders, the selected page, and that account's own download history, under `%AppData%\win-harden`. Each account runs its own tray monitor over its own Downloads folder, and the two can run the app at the same time. Uninstall removes that folder from every profile after restoring system settings.

### Getting a built installer without building it

Download the installer and its `.sha256` file from [GitHub Releases](https://github.com/fleetwoodjohnr/windows_firewall/releases). Run the `.exe` and follow the wizard; it installs the application and its dependencies for every account on the PC.

Development builds are also available from successful [Windows package workflow runs](https://github.com/fleetwoodjohnr/windows_firewall/actions/workflows/windows.yml), in the `win-harden-windows-x64` artifact. A failed workflow does not produce an installer. Download `windows-build-diagnostics` from that run for the build transcript and syntax report.

The GitHub-hosted Windows image disables some Defender protections and excludes its build drives. The workflow first enables the protections required for scanning and removes the image's `C:\` and `D:\` exclusions on that disposable runner. This preparation script refuses to run outside GitHub-hosted CI and is not included in the installed application. Dependency scans remain mandatory.

Confirm the hash on the target PC before running a manually downloaded installer:

```powershell
Get-FileHash .\WinHardenSetup-1.2.1.exe -Algorithm SHA256
```

Windows Server CI builds the package; it does not establish Windows 11 acceptance. Run the checklist below on the target laptop.

Pinned build inputs are in `requirements-win.lock` and `scripts/downloads.json`. Upstream changes, including changes to the vendor's unversioned Sysmon archive, fail verification until the manifest is reviewed and updated. Build staging is under `%ProgramData%\win-harden-build`.

### Unsigned installers and SmartScreen

The installer is not code-signed, so Windows shows **Windows protected your PC**. Choose **More info**, confirm the app name, then **Run anyway**. The UAC prompt that follows reports `Publisher: Unknown`. This is expected and will keep happening for every release; signing is the only thing that removes it.

Because there is no publisher identity, verify the download yourself before running it. Compare the output of the `Get-FileHash` command above against the `.sha256` asset published beside the installer; they must match exactly. SHA-256 establishes integrity against the release assets, not a code-signing identity.

## Application updates

Open **Updates** or select **Check for application updates** in the tray menu. The installed app checks after startup when due and once every 24 hours while running. It notifies you once per available version. A check that fails because the PC is offline or GitHub rate-limits it retries after 30 minutes rather than waiting a full day. Turn off automatic checks on the Updates page if you prefer to check manually.

Click **Update** to download the complete installer. The app checks its size and SHA-256 checksum before opening the upgrade wizard. Downloading does not require administrator rights; installing does. The GUI stays running until setup asks to close it, so cancelling administrator approval or leaving the wizard before installation keeps monitoring available. No source checkout, Git account, Python installation, or subscription is needed on the target PC.

During an upgrade, the scanner service stops, the application files are replaced, and the service starts again. Preferences, watched folders, history, queued scan records, and the original-settings journal are retained. Active scans may be interrupted and reported incomplete. Wait for security changes to finish before upgrading. Close the app and **Exit monitor** in other signed-in accounts when setup requests it, then reopen their monitors afterward. Cancelling setup before replacement restarts the old service; failures during installation require rerunning the same installer to repair it. Same-version repair is supported; newer installers refuse downgrades.

Downloads are staged under `%LocalAppData%\win-harden\updates`. Invalid and cancelled downloads are removed. A completed upgrade closes the app while setup is still running, so that installer is cleared on the next launch instead. A launched installer may remain cached until uninstall and can be removed after setup finishes. Offline checks, GitHub rate limits, missing assets and corrupt downloads produce a message on the Updates page. They do not replace application files. Development checkouts can check releases but cannot install updates.

Version 1.2.0 is the first published release and introduces the updater, so it has to be installed manually from GitHub Releases; there is no earlier release to update from. Every version after it can be installed through the app. Defender definition updates remain a separate action on **Virus Scan**.

### Publishing a new version

1. Change `VERSION` in `win_harden/version.py` to the next `major.minor.patch` version. The GUI, all three executables, installer filename and Windows version metadata use that value.
2. Commit and push the code to `main`. Confirm the Windows package job passes and verify its candidate installer on Windows 11 using [the acceptance checklist](docs/WINDOWS-VERIFICATION.md).
3. Tag that exact verified commit and push the tag. For version 1.2.1:

   ```bash
   git tag v1.2.1 <verified-commit-sha>
   git push origin v1.2.1
   ```

The tag workflow checks the version, builds and tests the installer, then creates a draft GitHub Release. It uploads the installer, checksum and dependency inventory, verifies their sizes and GitHub SHA-256 digests, and publishes the complete release as latest. Build and upload failures leave no public update. Resolve the failure and rerun a draft release's workflow; an already-published release must be followed by a new version. Branch pushes and pull requests only create build artifacts.

A release is created as a draft, and only becomes public after its uploaded assets are verified and the published release is re-read and parsed the way the updater parses it. A release that cannot be consumed is returned to draft rather than left discoverable. Re-running the job for the same tag reuses the existing draft instead of creating a second one.

Signing, if a certificate is ever obtained, attaches in `scripts/build.ps1` between the Inno Setup compile and the `Get-FileHash` sidecar, and to the three executables before PyInstaller collects them. No signing code is present today.

The publishing job uses GitHub's built-in workflow token with `contents: write`; no token is included in the installed application. Repository or organization policy must allow that job to write releases. Installer compilation requires Windows; it cannot be produced by running the Python build on Linux.

## Virus scans and downloads

**Virus Scan** provides quick, full, file and folder scans, definition updates, Defender status, recent results, and removal of active threats. Defender performs its configured quarantine/removal actions. **Remove active threats** requires UAC and applies to all active threats on the PC. Use Windows Security to review quarantine, remaining actions and restart requests; the app never restores quarantined malware automatically.

The tray monitor starts at sign-in and watches the current user's Windows Downloads known folder. Add other local download destinations on the Virus Scan page. Closing the window leaves the monitor running; **Exit monitor** stops the additional scans. Defender continues independently. Downloads completed while the monitor was stopped are reconciled when it starts again.

Temporary browser download files are deferred until renamed and stable. Changed files receive a new scan. Jobs and retries survive restarts, and interrupted work is reported as incomplete. Watched folders are scanned recursively; linked folders, network/device paths, alternate data streams and paths over 240 characters are refused or reported. Folder scans submit only files readable by the requesting user.

**This is not a guarantee that every download is safe.** Microsoft Defender real-time and downloaded-file protection provide system-wide protection. The monitor adds scans in watched folders; it does not intercept every browser or prevent a pending file from being opened. Downloads saved elsewhere need a watched folder or a manual scan. Defender exclusions, encrypted archives, unsupported content, stale definitions, offline cloud checks and an unavailable engine can limit coverage. A verified result says **No threats detected**, and belongs to the content scanned at that time. Unverified completion or changed content never receives that result.

## Firewall and hardening

Firewall profiles can be active simultaneously. Rule groups shared across profiles show their affected profiles before changes. Panic mode adds application-owned inbound/outbound block rules and records the prior profile settings; turning it off restores those settings. Apply panic mode only at the physical machine.

Every switch uses the same state language as the Fedora application: red with the thumb on the left means **Off**, and green with the thumb on the right means **On**. The colour reports whether the Windows feature or rule is enabled, not whether enabling it is the safer choice. Read the risk marker and expanded explanation beside firewall rules before changing them. Machine-setting switches do not move while a confirmation or Administrator prompt is open; they move only after Windows confirms the change. A cancelled or refused change leaves the original position visible.

Protection and Hardening contain six families, each with Off / Basic / Balanced / Strict choices: Defender/ASR, exploit protection, network exposure, credential protection, DNS privacy, and TLS/crypto. Read each level's compatibility notes before applying it. BitLocker is reported, not enabled by the app. A recovery protector being present does **not** prove the recovery key has been backed up.

Level changes, panic mode, selected DNS providers, and the Enable download protection action record originals before mutation in `%ProgramData%\win-harden\state.json`. Downgrading a level restores settings it no longer uses. Revert restores original values, including absence, and respects settings shared by multiple families. Individual firewall rules, network category choices, ASR overrides and direct component switches are explicit settings and can persist independently of levels. Antivirus remediation and optional software installation are not undone by reverting a hardening level.

Uninstall first stops the scanner and restores journalled settings. If restoration fails, it retains the application and journal for retry. Do not delete that journal to bypass a failure. Legacy records that did not preserve an original unset state require manual reconciliation; the app refuses to invent an original value. Policy, Tamper Protection and reboot requirements are reported rather than bypassed.

## Verification

Run the installed verification script from **Administrator Windows PowerShell**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\win-harden\scripts\verify-windows.ps1" -RunScan
```

It writes `win-harden-verification.json` to your Desktop. See [the Windows verification checklist](docs/WINDOWS-VERIFICATION.md) for installation, sign-in monitoring, safe EICAR testing, UAC, reboot and uninstall tests. Windows API, Defender and installer behavior require those checks on actual Windows 11; Linux tests and Windows Server CI do not establish Windows 11 acceptance.

For portable development tests:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install PySide6 pytest
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest tests -q
```

Tests exercise protocol validation, original-state restoration, scan result classification, queue ownership/recovery, download lifecycle, package wiring and Qt pages. The Windows workflow also parses scripts with Windows PowerShell 5.1, builds the frozen package and uploads the installer artifacts. It must be run before distributing a build.

Microsoft references: [Defender command-line behavior](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus), [scan events](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus), [exclusions](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure), [downloaded-file protection](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference).
