$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$out = @{ available = $false }
try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $p = Get-MpPreference -ErrorAction Stop
    $out.available = [bool]($s.AMServiceEnabled -and $s.AntivirusEnabled -and $s.AMRunningMode -ne 'Passive')
    $out.mode = [string]$s.AMRunningMode
    $out.realtimeProtection = [bool]$s.RealTimeProtectionEnabled
    $out.downloadProtection = -not [bool]$p.DisableIOAVProtection
    $out.behaviorMonitor = [bool]$s.BehaviorMonitorEnabled
    $out.tamperProtected = [bool]$s.IsTamperProtected
    $out.signatureVersion = [string]$s.AntivirusSignatureVersion
    $out.signatureAgeDays = [int]$s.AntivirusSignatureAge
    $out.lastQuickScan = [string]$s.QuickScanEndTime
    $out.lastFullScan = [string]$s.FullScanEndTime
    $out.activeThreats = @((Get-MpThreat -ErrorAction Stop) | Where-Object { $_.IsActive }).Count
    if (-not $out.available) { $out.error = 'Defender is disabled or passive. Check the active antivirus in Windows Security.' }
} catch { $out.available = $false; $out.error = $_.Exception.Message }
$out | ConvertTo-Json -Depth 5 -Compress
