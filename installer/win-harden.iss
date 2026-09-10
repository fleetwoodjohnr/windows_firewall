#define AppName "Windows Firewall & Hardening"
#ifndef AppVersion
  #error AppVersion must be supplied by scripts\build.ps1
#endif
[Setup]
AppId={{7C4A1E62-9B3D-4F58-8E21-6D0F5A9C2B14}
AppName={#AppName}
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}.0
AppUpdatesURL=https://github.com/fleetwoodjohnr/windows_firewall/releases
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
CloseApplications=yes
RestartApplications=no
SetupMutex=WinHardenSetup,Global\WinHardenSetup
SetupLogging=yes
UsePreviousTasks=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "extras_defender"; Description: "Update Microsoft Defender definitions"; GroupDescription: "Optional extras:"; Flags: unchecked
Name: "extras_sysmon"; Description: "Install Microsoft Sysmon with vendor defaults"; GroupDescription: "Optional extras:"; Flags: unchecked
Name: "extras_lgpo"; Description: "Open Microsoft's security baseline download page"; GroupDescription: "Optional extras:"; Flags: unchecked

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
Filename: "https://www.microsoft.com/en-us/download/details.aspx?id=55319"; Tasks: extras_lgpo; Flags: shellexec runasoriginaluser
Filename: "{app}\win-harden.exe"; Description: "Open {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
// This is a machine-wide install, and deliberately so: the laptop it targets has
// more than one account. The program lives in Program Files, its shortcuts and
// the sign-in download monitor are created for every account, and every change
// the broker makes is machine-wide (HKLM, Windows Firewall, Defender, services).
// The only per-account state is each user's own preferences under AppData, which
// is why uninstall has to walk the profile list rather than just its own.
const
  PROFILE_LIST = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList';
  UNINSTALL_KEY = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{7C4A1E62-9B3D-4F58-8E21-6D0F5A9C2B14}_is1';

var
  ScannerStopped: Boolean;
  ReplacementStarted: Boolean;
  ScannerReady: Boolean;

function InitializeSetup(): Boolean;
var
  Installed: String;
  OldVersion, NewVersion: Int64;
begin
  Result := True;
  if RegQueryStringValue(HKLM64, UNINSTALL_KEY, 'DisplayVersion', Installed) then
  begin
    if not StrToVersion(Installed, OldVersion) or not StrToVersion('{#AppVersion}', NewVersion) then
    begin
      MsgBox('The installed version could not be read. Repair with the current installer before changing versions.', mbError, MB_OK);
      Result := False;
    end
    else if ComparePackedVersion(OldVersion, NewVersion) > 0 then
    begin
      MsgBox('A newer version (' + Installed + ') is already installed. Download the latest installer from GitHub Releases.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

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
  begin
    if not RunHelper('win-harden-scanner.exe', '--stop') then
      Result := 'The scan service could not stop. Restart Windows and retry setup.'
    else
      ScannerStopped := True;
  end;
end;

procedure DeinitializeSetup();
begin
  // Preparing to Install runs before Restart Manager asks to close other apps.
  if ScannerStopped and not ScannerReady and not ReplacementStarted then
    if not RunHelper('win-harden-scanner.exe', '--install') then
      MsgBox('Setup was cancelled, but the scan service could not restart. Run setup again to repair it. Your settings and scan history have been kept.', mbError, MB_OK);
  if ReplacementStarted and not ScannerReady then
    MsgBox('Installation did not complete. Run this installer again to repair the application and scan service. Your settings and scan history have been kept.', mbError, MB_OK);
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
  if CurStep = ssInstall then
    ReplacementStarted := True;
  if CurStep = ssPostInstall then
  begin
    if not RunHelper('win-harden-scanner.exe', '--install') then
      RaiseException('The scan service could not be installed or started. Run setup again to repair it.');
    ScannerReady := True;
    RunExtra('extras_defender', '-DefenderSignatures');
    RunExtra('extras_sysmon', '-Sysmon');
  end;
end;

function UpdateReadyMemo(const Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine +
    'Accounts:' + NewLine +
    Space + 'All user accounts on this PC.' + NewLine +
    Space + 'Shortcuts and the sign-in download monitor are created for every account,' + NewLine +
    Space + 'and firewall, Defender and hardening changes apply to the whole machine.' + NewLine +
    Space + 'Applying a change always needs Administrator approval (UAC).' + NewLine;
  Result := Result + NewLine + 'Upgrading:' + NewLine +
    Space + 'Existing settings, watched folders and scan history are kept.' + NewLine +
    Space + 'Close the app and Exit monitor in other signed-in accounts when prompted.' + NewLine +
    Space + 'Reopen the monitor in those accounts after installation.' + NewLine;
  if MemoTasksInfo <> '' then
    Result := Result + NewLine + MemoTasksInfo + NewLine;
end;

// Preferences only. System state was already restored by --revert-all above.
procedure RemovePerUserData();
var
  Accounts: TArrayOfString;
  I: Integer;
  Profile: String;
begin
  if not RegGetSubkeyNames(HKEY_LOCAL_MACHINE, PROFILE_LIST, Accounts) then
    Exit;
  for I := 0 to GetArrayLength(Accounts) - 1 do
  begin
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, PROFILE_LIST + '\' + Accounts[I],
      'ProfileImagePath', Profile) then
      Continue;
    // Only ever this one folder name, and only under a profile Windows itself
    // reported. Never a path assembled from anything the uninstaller was told.
    if (Profile <> '') and DirExists(Profile + '\AppData\Roaming\win-harden') then
      DelTree(Profile + '\AppData\Roaming\win-harden', True, True, True);
    if (Profile <> '') and DirExists(Profile + '\AppData\Local\win-harden\updates') then
      DelTree(Profile + '\AppData\Local\win-harden\updates', True, True, True);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemovePerUserData();
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
