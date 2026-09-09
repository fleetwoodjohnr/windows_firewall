; Inno Setup script for Windows Firewall & Hardening.
;
; The installer is self-contained: it carries a bundled CPython and Qt and
; fetches nothing at install time. Everything the build needed was downloaded on
; the build machine by scripts\bootstrap.ps1, so an end user with no internet,
; a proxy, or a locked-down network still gets a working install.
;
; The uninstaller does one thing most uninstallers do not: it reverts every
; change the app applied before removing any files. A hardening tool that leaves
; its settings behind is worse than one that was never installed -- the settings
; outlive the app that explains them, and nobody is left who knows what changed.

#define AppName "Windows Firewall & Hardening"
#define AppShortName "win-harden"
#define AppVersion "1.0.0"
#define AppPublisher "jrf"
#define AppExe "win-harden.exe"

[Setup]
AppId={{7C4A1E62-9B3D-4F58-8E21-6D0F5A9C2B14}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppShortName}
DefaultGroupName={#AppName}
OutputDir=Output
OutputBaseFilename=WinHardenSetup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; The app itself runs unelevated; installing into Program Files needs admin.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 11 (10.0.22000). The app targets features that do not exist earlier.
MinVersion=10.0.22000
UninstallDisplayIcon={app}\{#AppExe}
LicenseFile=..\LICENSE
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

; Every extra is opt-in, separately declinable, and separately reversible.
; Nothing here is applied silently, and none of it is needed for the app to work.
Name: "extras"; Description: "Additional security tooling (optional)"; GroupDescription: "Extras:"; Flags: unchecked
Name: "extras\defender"; Description: "Update Microsoft Defender's signatures now"; GroupDescription: "Extras:"; Flags: unchecked
Name: "extras\sysmon"; Description: "Install Sysmon with a vetted logging configuration"; GroupDescription: "Extras:"; Flags: unchecked
Name: "extras\lgpo"; Description: "Download Microsoft's Security Compliance Toolkit and Windows 11 baseline"; GroupDescription: "Extras:"; Flags: unchecked

[Files]
Source: "..\dist\win-harden\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\scripts\extras.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Extras run after the files are in place, each gated on its own checkbox.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\extras.ps1"" -DefenderSignatures"; \
  StatusMsg: "Updating Defender signatures..."; Flags: runhidden waituntilterminated; Tasks: extras\defender

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\extras.ps1"" -Sysmon"; \
  StatusMsg: "Installing Sysmon..."; Flags: runhidden waituntilterminated; Tasks: extras\sysmon

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\extras.ps1"" -SecurityBaseline"; \
  StatusMsg: "Downloading the Security Compliance Toolkit..."; Flags: runhidden waituntilterminated; Tasks: extras\lgpo

; The app itself is launched unelevated, as the signed-in user -- not as the
; elevated installer, which would leave it running with rights it must not have.
Filename: "{app}\{#AppExe}"; Description: "Open {#AppName}"; \
  Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Revert BEFORE the files are removed: the broker doing the reverting is one of
; the files. RunOnceId keeps this to a single execution.
Filename: "{app}\win-harden-broker.exe"; Parameters: "--revert-all"; \
  RunOnceId: "RevertHardening"; Flags: runhidden waituntilterminated; \
  StatusMsg: "Putting your settings back the way they were..."

[UninstallDelete]
Type: filesandordirs; Name: "{app}\scripts"
Type: dirifempty; Name: "{app}"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // The state file records anything that could not be put back, so it is left
    // deliberately: reinstalling and reverting again will retry those.
    MsgBox('Your settings have been restored to how they were before this app was installed.'#13#10#13#10 +
           'If anything could not be put back, it is listed in:'#13#10 +
           ExpandConstant('{commonappdata}') + '\win-harden\broker.log',
           mbInformation, MB_OK);
  end;
end;
