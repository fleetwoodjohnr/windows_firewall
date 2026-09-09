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
    [string]$Action
)
$ErrorActionPreference = 'Stop'

$mpAction = switch ($Action) {
    'off'   { 'Disabled' }
    'audit' { 'AuditMode' }
    'warn'  { 'Warn' }
    'block' { 'Enabled' }
}

try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleId `
                     -AttackSurfaceReductionRules_Actions $mpAction
}
catch {
    Write-Error "Could not set ASR rule $RuleId to $Action. $($_.Exception.Message)"
    exit 1
}

@{ rule = $RuleId; action = $Action } | ConvertTo-Json -Compress
