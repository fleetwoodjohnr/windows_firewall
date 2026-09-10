<# Enable verified download scanning on disposable GitHub-hosted build machines.
   The upstream image excludes C:\ and D:\ and disables archive scanning:
   https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Configure-WindowsDefender.ps1
   This script is CI-only and is not shipped by the installer. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Runner preparation is restricted to disposable GitHub-hosted machines.'
}
if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Prepare the Windows x64 runner using 64-bit PowerShell.'
}

Write-Host 'Preparing Microsoft Defender to verify build downloads...'
# Undo only the passive-mode policy used by the upstream runner image. This
# enables protection; no Tamper Protection or antivirus bypass is used.
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
if (Test-Path -LiteralPath $policy) {
    $passive = Get-ItemProperty -LiteralPath $policy -Name ForceDefenderPassiveMode -ErrorAction SilentlyContinue
    if ($passive.ForceDefenderPassiveMode -eq 1) {
        Set-ItemProperty -LiteralPath $policy -Name ForceDefenderPassiveMode -Value 0 -Type DWord
    }
}
Set-MpPreference -DisableArchiveScanning $false -DisableRealtimeMonitoring $false `
    -DisableIOAVProtection $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false
$preferences = Get-MpPreference -ErrorAction Stop
foreach ($path in @($preferences.ExclusionPath)) {
    if ($path -match '^[CD]:\\?$') {
        Write-Host "Removing the runner image's whole-drive scan exclusion: $path"
        Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
    }
}

$deadline = (Get-Date).AddMinutes(2)
do {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $preferences = Get-MpPreference -ErrorAction Stop
    $ready = $status.AMServiceEnabled -and $status.AntivirusEnabled -and
        $status.RealTimeProtectionEnabled -and -not $preferences.DisableArchiveScanning -and
        -not $preferences.DisableIOAVProtection -and
        -not @($preferences.ExclusionPath | Where-Object { $_ -match '^[CD]:\\?$' }).Count
    if ($ready) { break }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

$status | Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion | Format-List | Out-Host
$preferences | Select-Object DisableArchiveScanning, DisableIOAVProtection, ExclusionPath | Format-List | Out-Host
if (-not $ready) {
    throw 'The hosted runner did not enable the required Defender protections. Build downloads will not be executed.'
}
Write-Host 'The runner is ready for verified download scanning.'
