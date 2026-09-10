<#
.SYNOPSIS
  Enables or disables the firewall for one profile.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Domain','Private','Public','All')][string]$Profile,
    [Parameter(Mandatory)][ValidateSet('on','off')][string]$State
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $enabled = if ($State -eq 'on') { 'True' } else { 'False' }
    if ($Profile -eq 'All') { Set-NetFirewallProfile -All -Enabled $enabled }
    else                    { Set-NetFirewallProfile -Profile $Profile -Enabled $enabled }
}
catch { Write-Error "Could not set the $Profile firewall profile $State. $($_.Exception.Message)"; exit 1 }
@{ profile = $Profile; state = $State } | ConvertTo-Json -Compress
