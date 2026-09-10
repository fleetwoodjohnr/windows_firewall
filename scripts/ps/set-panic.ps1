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
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$names = @('WinHarden-Panic-In-v1','WinHarden-Panic-Out-v1')
try {
    if ($State -eq 'on') {
        Set-NetFirewallProfile -All -Enabled True
        foreach ($direction in @('Inbound','Outbound')) {
            $name = if ($direction -eq 'Inbound') { $names[0] } else { $names[1] }
            Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule -Name $name -DisplayName "WinHarden panic: $direction" -Group 'WinHarden panic' `
                -Direction $direction -Action Block -Enabled True -Profile Any -Protocol Any | Out-Null
        }
        $active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $names | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
        $disabled = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled -ne 'True' })
        if ($active.Count -ne 2 -or $disabled.Count) { throw 'Windows policy prevented panic mode from being enforced.' }
    } else {
        foreach ($name in $names) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
        # The broker restores the captured profile settings.
    }
}
catch { Write-Error "Could not turn panic mode $State. $($_.Exception.Message)"; exit 1 }
@{ panicMode = ($State -eq 'on') } | ConvertTo-Json -Compress
