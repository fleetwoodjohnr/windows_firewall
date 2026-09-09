<#
.SYNOPSIS
  Lists inbound firewall rule groups for one profile, with how many rules in
  each are enabled. Unprivileged, changes nothing.

  Windows groups its built-in rules by display group -- "File and Printer
  Sharing", "Remote Desktop", "Network Discovery" -- and those groups are the
  closest equivalent to firewalld's services. A group is reported as enabled
  only when EVERY inbound rule in it is enabled; a partially-enabled group is
  reported as such rather than rounded to on or off, because rounding would make
  the toggle lie about what is actually open.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Domain','Private','Public','All')]
    [string]$Profile
)
$ErrorActionPreference = 'Stop'

try {
    $rules = Get-NetFirewallRule -Direction Inbound -ErrorAction Stop |
             Where-Object { $Profile -eq 'All' -or $_.Profile -match $Profile -or $_.Profile -eq 'Any' }

    $groups = @()
    foreach ($g in ($rules | Group-Object -Property DisplayGroup)) {
        if ([string]::IsNullOrWhiteSpace($g.Name)) { continue }
        $enabled = @($g.Group | Where-Object { $_.Enabled -eq 'True' }).Count
        $groups += [ordered]@{
            name    = [string]$g.Name
            total   = [int]$g.Count
            enabled = [int]$enabled
            # Three states, not two. "partial" is a real condition and the UI
            # shows it rather than guessing.
            state   = if ($enabled -eq 0) { 'off' }
                      elseif ($enabled -eq $g.Count) { 'on' }
                      else { 'partial' }
        }
    }
    @{ profile = $Profile; groups = @($groups | Sort-Object { $_.name }) } |
        ConvertTo-Json -Depth 5 -Compress
}
catch {
    Write-Error "Firewall rules could not be listed: $($_.Exception.Message)"
    exit 1
}
