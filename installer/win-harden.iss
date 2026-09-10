#define AppName "Windows Firewall & Hardening"
#define AppVersion "1.1.0"
[Setup]
AppId={{7C4A1E62-9B3D-4F58-8E21-6D0F5A9C2B14}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=jrf
DefaultDirName={autopf}\win-harden
DefaultGroupName={#AppName}
OutputDir=Output
OutputBaseFilename=WinHardenSetup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.22000
UninstallDisplayIcon={app}\win-harden.exe
SetupIconFile=..\build\win-harden.ico
LicenseFile=..\LICENSE
DisableProgramGroupPage=yes
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "extras-defender"; Description: "Update Microsoft Defender definitions"; GroupDescription: "Optional extras:"; Flags: unchecked
Name: "extras-sysmon"; Description: "Install Microsoft Sysmon with vendor defaults"; GroupDescription: "Optional extras:"; Flags: unchecked
Name: "extras-lgpo"; Description: "Open Microsoft's security baseline download page"; GroupDescription: "Optional extras:"; Flags: unchecked

[Files]
Source: "..\dist\win-harden\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\scripts\extras.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\scripts\secure-download.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\scripts\downloads.json"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\scripts\verify-windows.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\WINDOWS-VERIFICATION.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\requirements-win.lock"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\win-harden.exe"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\win-harden.exe"; Tasks: desktopicon
Name: "{commonstartup}\WinHarden download monitor"; Filename: "{app}\win-harden.exe"; Parameters: "--background"

[Run]
Filename: "https://www.microsoft.com/en-us/download/details.aspx?id=55319"; Tasks: extras-lgpo; Flags: shellexec runasoriginaluser
Filename: "{app}\win-harden.exe"; Description: "Open {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
function RunHelper(const Name, Args: String): Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{app}\') + Name, Args, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code);
  if Result then Result := Code = 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\win-harden-scanner.exe')) then
    if not RunHelper('win-harden-scanner.exe', '--stop') then
      Result := 'The scan service could not stop. Restart Windows and retry setup.';
end;

procedure RunExtra(const TaskName, Flag: String);
var Code: Integer;
begin
  if WizardIsTaskSelected(TaskName) then
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\scripts\extras.ps1') + '" ' + Flag,
      ExpandConstant('{app}'), SW_SHOWNORMAL, ewWaitUntilTerminated, Code) or (Code <> 0) then
      MsgBox('The optional task ' + TaskName + ' failed. The application is installed; retry this extra from scripts\extras.ps1 to see its error.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not RunHelper('win-harden-scanner.exe', '--install') then
      RaiseException('The scan service could not be installed or started. Run setup again to repair it.');
    RunExtra('extras-defender', '-DefenderSignatures');
    RunExtra('extras-sysmon', '-Sysmon');
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := False;
  if not RunHelper('win-harden-scanner.exe', '--stop') then
  begin
    MsgBox('The scan service could not stop. Restart Windows and retry uninstall.', mbError, MB_OK);
    Exit;
  end;
  if not RunHelper('win-harden-broker.exe', '--revert-all') then
  begin
    MsgBox('Some original settings could not be restored. The app and restore journal have been retained.'#13#10 +
      'Review C:\ProgramData\win-harden\broker.log, resolve the problem, and retry uninstall.', mbError, MB_OK);
    RunHelper('win-harden-scanner.exe', '--install');
    Exit;
  end;
  if not RunHelper('win-harden-scanner.exe', '--remove') then
  begin
    MsgBox('The scan service could not be removed. Restart Windows and retry uninstall.', mbError, MB_OK);
    Exit;
  end;
  Result := True;
end;
