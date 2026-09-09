<#
.SYNOPSIS
  Panic mode: block all traffic, in and out, on every profile.

  The equivalent of firewalld's panic mode, and the same warning applies -- this
  drops existing connections, so applying it over a remote session ends that
  session. Reverting sets both default actions back to NotConfigured, which is
  Windows' own default, rather than to Allow.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('on','off')][string]$State)
$ErrorActionPreference = 'Stop'
try {
    if ($State -eq 'on') {
        Set-NetFirewallProfile -All -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Block
    } else {
        Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured `
            -DefaultOutboundAction NotConfigured
    }
}
catch { Write-Error "Could not turn panic mode $State. $($_.Exception.Message)"; exit 1 }
@{ panicMode = ($State -eq 'on') } | ConvertTo-Json -Compress
