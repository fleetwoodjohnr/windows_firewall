<#
.SYNOPSIS
  Enables or disables every inbound rule in one firewall rule group, for one
  profile.

  Group is the only parameter carrying text this app did not author: Windows
  supplies the display group names and the GUI hands one back. It is bound as a
  parameter and passed to Enable/Disable-NetFirewallRule as data -- never
  interpolated into a command string -- and the Python side additionally
  restricts it to a character set that cannot resemble PowerShell syntax.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Domain','Private','Public','All')][string]$Profile,
    [Parameter(Mandatory)][ValidatePattern("^[A-Za-z0-9 ()/.,+&_'-]{1,128}$")][string]$Group,
    [Parameter(Mandatory)][ValidateSet('on','off')][string]$State
)
$ErrorActionPreference = 'Stop'

try {
    $rules = Get-NetFirewallRule -DisplayGroup $Group -Direction Inbound -ErrorAction Stop
    if ($Profile -ne 'All') {
        $rules = $rules | Where-Object { $_.Profile -match $Profile -or $_.Profile -eq 'Any' }
    }
    if (-not $rules) {
        Write-Error "No inbound firewall rules were found in the group '$Group'."
        exit 1
    }
    if ($State -eq 'on') { $rules | Enable-NetFirewallRule }
    else                 { $rules | Disable-NetFirewallRule }
    @{ group = $Group; profile = $Profile; state = $State; rules = @($rules).Count } |
        ConvertTo-Json -Compress
}
catch { Write-Error "Could not turn the '$Group' rules $State. $($_.Exception.Message)"; exit 1 }
