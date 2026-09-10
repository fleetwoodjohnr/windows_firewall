<#
.SYNOPSIS
  Reads Microsoft Defender's current state. Unprivileged, changes nothing.

  Tamper Protection is reported first and matters most: when it is on, most of
  Set-MpPreference is silently discarded, so the app refuses to apply a Defender
  level rather than appear to work. If Defender cannot be read at all we report
  isTamperProtected = true, because the safe assumption when we cannot tell is
  the one that stops us claiming protection we have not verified.
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$out = [ordered]@{}
function Convert-MpEnum {
    param($Value, [hashtable]$Names)
    if ($null -eq $Value) { throw 'Defender did not report a preference value.' }
    $number = 0
    if ([int]::TryParse([string]$Value, [ref]$number)) {
        if (-not $Names.ContainsKey($number)) { throw "Unknown Defender preference value $number" }
        return $Names[$number]
    }
    return [string]$Value
}

try {
    $status = Get-MpComputerStatus
    $out.isTamperProtected  = [bool]$status.IsTamperProtected
    $out.realtimeProtection = [bool]$status.RealTimeProtectionEnabled
    $out.antivirusEnabled   = [bool]$status.AntivirusEnabled
    $out.behaviorMonitor    = [bool]$status.BehaviorMonitorEnabled
    $out.signatureVersion   = [string]$status.AntivirusSignatureVersion
    $out.signatureAgeDays   = [int]$status.AntivirusSignatureAge
    $out.lastQuickScan      = if ($status.QuickScanEndTime) { $status.QuickScanEndTime.ToString('o') } else { $null }
    $out.lastFullScan       = if ($status.FullScanEndTime)  { $status.FullScanEndTime.ToString('o') }  else { $null }
}
catch {
    # Could not read Defender. Assume tampered rather than assume safe.
    $out.isTamperProtected = $true
    $out.error = "Microsoft Defender could not be read: $($_.Exception.Message)"
    $out | ConvertTo-Json -Depth 5 -Compress
    exit 0
}

try {
    $p = Get-MpPreference
    $out.preferences = [ordered]@{
        mapsReporting          = Convert-MpEnum $p.MAPSReporting @{0='Disabled';1='Basic';2='Advanced'}
        submitSamples          = Convert-MpEnum $p.SubmitSamplesConsent @{0='AlwaysPrompt';1='SendSafeSamples';2='NeverSend';3='SendAllSamples'}
        cloudBlockLevel        = Convert-MpEnum $p.CloudBlockLevel @{0='Default';1='Moderate';2='High';4='HighPlus';6='ZeroTolerance'}
        cloudExtendedTimeout   = [string]$p.CloudExtendedTimeout
        puaProtection          = Convert-MpEnum $p.PUAProtection @{0='Disabled';1='Enabled';2='AuditMode'}
        controlledFolderAccess = Convert-MpEnum $p.EnableControlledFolderAccess @{0='Disabled';1='Enabled';2='AuditMode';3='BlockDiskModificationOnly';4='AuditDiskModificationOnly'}
        networkProtection      = Convert-MpEnum $p.EnableNetworkProtection @{0='Disabled';1='Enabled';2='AuditMode'}
        realtimeMonitoring     = [string](-not $p.DisableRealtimeMonitoring)
        ioavProtection         = [string](-not $p.DisableIOAVProtection)
    }

    # Ids and actions are two parallel arrays. Zipping them by index is the only
    # way Defender exposes the pairing.
    $ids     = @($p.AttackSurfaceReductionRules_Ids)
    $actions = @($p.AttackSurfaceReductionRules_Actions)
    $rules = @()
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $rules += [ordered]@{
            id     = [string]$ids[$i]
            action = if ($i -lt $actions.Count) { [int]$actions[$i] } else { 0 }
        }
    }
    $out.asrRules = $rules
}
catch {
    $out.error = "Defender preferences could not be read: $($_.Exception.Message)"
}

$out | ConvertTo-Json -Depth 5 -Compress
