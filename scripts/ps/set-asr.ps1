<#
.SYNOPSIS
  Sets one Attack Surface Reduction rule's action.

  Uses Add-MpPreference rather than Set-MpPreference: Set- replaces the whole
  rule array, so setting one rule with it would silently clear every other rule
  already configured. Add- updates the named rule and leaves the rest alone.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$')]
    [string]$RuleId,

    [Parameter(Mandatory)]
    [ValidateSet('off','audit','warn','block')]
    [string]$Action,
    [ValidateSet('yes','no')][string]$Reset = 'no'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$mpAction = switch ($Action) {
    'off'   { 'Disabled' }
    'audit' { 'AuditMode' }
    'warn'  { 'Warn' }
    'block' { 'Enabled' }
}

try {
    if ($Reset -eq 'yes') {
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $RuleId
    } else {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleId `
                         -AttackSurfaceReductionRules_Actions $mpAction
    }
    $p = Get-MpPreference
    $ids = @($p.AttackSurfaceReductionRules_Ids)
    $index = -1
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i].Trim('{}') -eq $RuleId.Trim('{}')) { $index = $i; break } }
    $expected = @{ off=0; audit=2; warn=6; block=1 }[$Action]
    if (($Reset -eq 'yes' -and $index -ge 0) -or ($Reset -ne 'yes' -and ($index -lt 0 -or [int]$p.AttackSurfaceReductionRules_Actions[$index] -ne $expected))) {
        throw 'Windows policy or Tamper Protection prevented this ASR change.'
    }
}
catch {
    Write-Error "Could not set ASR rule $RuleId to $Action. $($_.Exception.Message)"
    exit 1
}

@{ rule = $RuleId; action = $Action } | ConvertTo-Json -Compress
