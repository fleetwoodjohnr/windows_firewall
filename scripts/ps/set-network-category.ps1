<#
.SYNOPSIS
  Sets one network's category to Public or Private.

  Domain is deliberately not offered: Windows assigns it itself when the machine
  is joined to and can reach a domain controller, and it cannot be set by hand.
  Public is the restrictive one -- it is what you want on any network you do not
  control.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{1,10}$')][string]$InterfaceIndex,
    [Parameter(Mandatory)][ValidateSet('Public','Private')][string]$Category
)
$ErrorActionPreference = 'Stop'
try {
    Set-NetConnectionProfile -InterfaceIndex ([int]$InterfaceIndex) -NetworkCategory $Category
}
catch { Write-Error "Could not set interface $InterfaceIndex to $Category. $($_.Exception.Message)"; exit 1 }
@{ interfaceIndex = [int]$InterfaceIndex; category = $Category } | ConvertTo-Json -Compress
