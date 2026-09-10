# Windows Firewall & Hardening

A Windows counterpart of [firewall-gui for Fedora](https://github.com/fleetwoodjohnr/fedora_firewall_gui), using Windows Firewall and Microsoft Defender. Targets **Windows 11, Intel/AMD x64**. ARM64 is not supported by this installer.

The six pages are Dashboard, Firewall Rules, Networks, Protection, Hardening, and **Virus Scan**. The GUI runs without administrator rights. Security changes use a separate helper through UAC; long antivirus operations run in a Windows service.

## Build and install

On Windows 11 x64, open **64-bit Windows PowerShell as Administrator** in this checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
```

The bootstrap automatically downloads the pinned Python runtime, Qt, pywin32, PyInstaller, test dependencies, and Inno Setup. Downloads use HTTPS and SHA-256 checks; vendor executables also require the expected Authenticode publisher. Microsoft Defender scans downloaded installers and dependency wheels before they are installed. Verification failure stops the build. Defender must be active with archive scanning enabled; restricted corporate policies may require administrator assistance. The script does not disable antivirus protection or create antivirus exclusions.

The build runs tests and checks the three frozen executables outside the source directory, then produces:

```text
installer\Output\WinHardenSetup-1.1.0.exe
installer\Output\WinHardenSetup-1.1.0.exe.sha256
```

Run that installer on the target PC. **Python, Qt and pywin32 are bundled:** the installed application does not need a separate Python installation, pip, winget, or a developer environment. Windows 11 supplies PowerShell, Windows Firewall and Defender. The installer installs the scan service and a sign-in shortcut for the tray monitor. Optional Sysmon and definition updates require internet access; Sysmon downloads are hash-checked, signature-checked and scanned. The optional baseline item opens Microsoft's download page for manual review.

Pinned build inputs are in `requirements-win.lock` and `scripts/downloads.json`. Upstream changes, including changes to the vendor's unversioned Sysmon archive, fail verification until the manifest is reviewed and updated. Build staging is under `%ProgramData%\win-harden-build`. This repository does not include a prebuilt or code-signed installer; a locally built installer can show an unknown-publisher prompt.

## Virus scans and downloads

**Virus Scan** provides quick, full, file and folder scans, definition updates, Defender status, recent results, and removal of active threats. Defender performs its configured quarantine/removal actions. **Remove active threats** requires UAC and applies to all active threats on the PC. Use Windows Security to review quarantine, remaining actions and restart requests; the app never restores quarantined malware automatically.

The tray monitor starts at sign-in and watches the current user's Windows Downloads known folder. Add other local download destinations on the Virus Scan page. Closing the window leaves the monitor running; **Exit monitor** stops the additional scans. Defender continues independently. Downloads completed while the monitor was stopped are reconciled when it starts again.

Temporary browser download files are deferred until renamed and stable. Changed files receive a new scan. Jobs and retries survive restarts, and interrupted work is reported as incomplete. Watched folders are scanned recursively; linked folders, network/device paths, alternate data streams and paths over 240 characters are refused or reported. Folder scans submit only files readable by the requesting user.

**This is not a guarantee that every download is safe.** Microsoft Defender real-time and downloaded-file protection provide system-wide protection. The monitor adds scans in watched folders; it does not intercept every browser or prevent a pending file from being opened. Downloads saved elsewhere need a watched folder or a manual scan. Defender exclusions, encrypted archives, unsupported content, stale definitions, offline cloud checks and an unavailable engine can limit coverage. A verified result says **No threats detected**, and belongs to the content scanned at that time. Unverified completion or changed content never receives that result.

## Firewall and hardening

Firewall profiles can be active simultaneously. Rule groups shared across profiles show their affected profiles before changes. Panic mode adds application-owned inbound/outbound block rules and records the prior profile settings; turning it off restores those settings. Apply panic mode only at the physical machine.

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
