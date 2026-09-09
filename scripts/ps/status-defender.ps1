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

$out = [ordered]@{}

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
        mapsReporting          = [string]$p.MAPSReporting
        submitSamples          = [string]$p.SubmitSamplesConsent
        cloudBlockLevel        = [string]$p.CloudBlockLevel
        cloudExtendedTimeout   = [string]$p.CloudExtendedTimeout
        puaProtection          = [string]$p.PUAProtection
        controlledFolderAccess = [string]$p.EnableControlledFolderAccess
        networkProtection      = [string]$p.EnableNetworkProtection
        realtimeMonitoring     = [string](-not $p.DisableRealtimeMonitoring)
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
