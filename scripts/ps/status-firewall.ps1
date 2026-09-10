<#
.SYNOPSIS
  Reads Windows Defender Firewall state. Unprivileged, changes nothing.

  Windows has exactly three profiles -- Domain, Private, Public -- and exactly
  one is active at a time, chosen by Windows from the network you are on. This
  is the structural difference from firewalld's arbitrary zones, and the reason
  the app's second page is a profile picker rather than a zone list.
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$out = [ordered]@{}

try {
    $profiles = @()
    foreach ($p in Get-NetFirewallProfile -All) {
        $profiles += [ordered]@{
            name                  = [string]$p.Name
            enabled               = [bool]$p.Enabled
            defaultInboundAction  = [string]$p.DefaultInboundAction
            defaultOutboundAction = [string]$p.DefaultOutboundAction
            notifyOnListen        = [bool]$p.NotifyOnListen
            logBlocked            = [string]$p.LogBlocked
        }
    }
    $out.profiles = $profiles
}
catch {
    $out.error = "The firewall could not be read: $($_.Exception.Message)"
    $out | ConvertTo-Json -Depth 5 -Compress
    exit 0
}

try {
    # Which profile is actually in force right now, per connected network.
    $active = @()
    foreach ($c in Get-NetConnectionProfile) {
        $active += [ordered]@{
            name           = [string]$c.Name
            interfaceIndex = [int]$c.InterfaceIndex
            interfaceAlias = [string]$c.InterfaceAlias
            category       = [string]$c.NetworkCategory
            ipv4           = [string]$c.IPv4Connectivity
        }
    }
    $out.activeNetworks = $active
}
catch {
    $out.activeNetworks = @()
}

# Panic mode, as this app defines it: every profile blocking inbound AND
# outbound. Reported rather than inferred from a stored flag, so a change made
# outside the app is visible.
$panicRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'WinHarden-Panic-In-v1','WinHarden-Panic-Out-v1' -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
$out.panicMode = ($panicRules.Count -eq 2) -and (@($out.profiles | Where-Object { -not $_.enabled }).Count -eq 0)

$out | ConvertTo-Json -Depth 5 -Compress
