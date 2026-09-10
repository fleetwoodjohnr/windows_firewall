<# Disposable GitHub-hosted Windows runner only. Installs, repairs and uninstalls the candidate. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Installer)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This installation smoke test is restricted to disposable GitHub-hosted runners.'
}
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$installDir = Join-Path $env:ProgramFiles 'win-harden'
if (Test-Path -LiteralPath $installDir) { throw 'The smoke test requires a clean machine without an existing installation.' }
$logs = Join-Path $env:RUNNER_TEMP 'installer-checks'
New-Item -ItemType Directory -Path $logs -Force | Out-Null

function Invoke-Setup {
    param([string]$Path, [string]$LogName)
    $log = Join-Path $logs $LogName
    $p = Start-Process -FilePath $Path -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/LOG=`"$log`"") -PassThru
    if (-not $p.WaitForExit(300000)) { throw "Setup timed out. Inspect $log" }
    $p.Refresh()
    if ($p.ExitCode -ne 0) { throw "Setup exited with code $($p.ExitCode). Inspect $log" }
}

function Assert-Installed {
    $version = (Get-Item -LiteralPath (Join-Path $installDir 'win-harden.exe')).VersionInfo.ProductVersion
    foreach ($name in @('win-harden','win-harden-broker','win-harden-scanner')) {
        $path = Join-Path $installDir "$name.exe"
        if ((Get-Item -LiteralPath $path).VersionInfo.ProductVersion -ne $version) { throw "Version mismatch: $name" }
        $p = Start-Process -FilePath $path -ArgumentList '--self-test' -WorkingDirectory $env:RUNNER_TEMP -PassThru
        if (-not $p.WaitForExit(120000)) { throw "$name self-test timed out." }
        $p.Refresh()
        if ($p.ExitCode -ne 0) { throw "$name self-test failed with $($p.ExitCode)." }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='WinHardenScanner'"
    if ($service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or $service.StartName -ne 'LocalSystem') {
        throw 'The installed scanner service is not running with the expected configuration.'
    }
    $shortcut = Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'WinHarden download monitor.lnk'
    if (-not (Test-Path -LiteralPath $shortcut)) { throw 'The all-accounts startup shortcut is missing.' }
    Write-Host "Installed version $version passed its runtime and service checks."
}

Invoke-Setup $installerPath 'install.log'
Assert-Installed
# Exercise preservation without changing any firewall/Defender settings.
$preferences = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'win-harden'
New-Item -ItemType Directory -Path $preferences -Force | Out-Null
$sentinel = Join-Path $preferences 'upgrade-preservation.txt'
'retain preferences during repair' | Set-Content -LiteralPath $sentinel
$before = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
Invoke-Setup $installerPath 'repair.log'
Assert-Installed
if ((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -ne $before) { throw 'Repair changed per-user data.' }
Invoke-Setup (Join-Path $installDir 'unins000.exe') 'uninstall.log'
if (Get-Service -Name WinHardenScanner -ErrorAction SilentlyContinue) { throw 'Uninstall left the scanner service installed.' }
if (Test-Path -LiteralPath (Join-Path $installDir 'win-harden.exe')) { throw 'Uninstall left the application executable installed.' }
Write-Host 'Installer, repair and uninstall smoke tests passed. Windows 11 acceptance still requires the manual checklist.'
