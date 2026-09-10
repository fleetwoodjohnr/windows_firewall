<#
.SYNOPSIS
  Turns one named system component on or off.

  Every branch is a fixed id from ValidateSet below -- the caller never names a
  service, a feature, or a registry path. That is the whole trust boundary for
  this script: the id selects the branch, and the branch decides what to touch.

  Remote Desktop is not guarded here. It is guarded in broker/guards.py, before
  this script is ever reached, because the check needs to know whether the
  *calling session* is a Remote Desktop session and that is not knowable from
  inside an elevated child process.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('openssh-server','smb1','rdp','winrm','remote-registry',
                 'firewall-domain','firewall-private','firewall-public',
                 'panic-mode','netbios','inbound-block','guest-account','wpad-service')]
    [string]$Toggle,

    [Parameter(Mandatory)]
    [ValidateSet('on','off')]
    [string]$State
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$on = ($State -eq 'on')

function Set-ServiceState {
    param([string]$Name, [bool]$Enabled)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { if ($Enabled) { throw "Service $Name is not installed or is unavailable." }; return }   # not installed is already the state we wanted
    if ($Enabled) {
        Set-Service -Name $Name -StartupType Automatic
        Start-Service -Name $Name -ErrorAction Stop
    } else {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        Set-Service -Name $Name -StartupType Disabled
    }
}

try {
    switch ($Toggle) {
        'openssh-server' {
            $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
            if ($on) {
                if ($cap -and $cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
                Set-ServiceState -Name 'sshd' -Enabled $true
            } else {
                # Switch the service off but leave the capability installed:
                # removing it discards the host keys, so re-enabling later would
                # present a changed fingerprint to every client that knows it.
                Set-ServiceState -Name 'sshd' -Enabled $false
            }
        }

        'smb1' {
            if ($on) { Enable-WindowsOptionalFeature  -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
            else     { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
        }

        'rdp' {
            $deny = if ($on) { 0 } else { 1 }
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
                             -Name 'fDenyTSConnections' -Value $deny -Type DWord
            if ($on) {
                Enable-NetFirewallRule -Name 'RemoteDesktop*' -ErrorAction Stop
                Set-ServiceState -Name 'TermService' -Enabled $true
            } else {
                Disable-NetFirewallRule -Name 'RemoteDesktop*' -ErrorAction Stop
            }
        }

        'winrm'           { Set-ServiceState -Name 'WinRM'               -Enabled $on }
        'remote-registry' { Set-ServiceState -Name 'RemoteRegistry'      -Enabled $on }
        'wpad-service'    { Set-ServiceState -Name 'WinHttpAutoProxySvc' -Enabled $on }

        'firewall-domain'  { Set-NetFirewallProfile -Profile Domain  -Enabled ([bool]$on) }
        'firewall-private' { Set-NetFirewallProfile -Profile Private -Enabled ([bool]$on) }
        'firewall-public'  { Set-NetFirewallProfile -Profile Public  -Enabled ([bool]$on) }

        'inbound-block' {
            $action = if ($on) { 'Block' } else { 'Allow' }
            Set-NetFirewallProfile -All -DefaultInboundAction $action
        }

        'panic-mode' { throw 'Panic mode must use its journalled broker operation.' }

        'netbios' {
            # Per-interface, under NetBT. 2 = disable NetBIOS over TCP/IP;
            # 0 = use the DHCP server's setting, which is the Windows default.
            $value = if ($on) { 0 } else { 2 }
            $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            foreach ($key in (Get-ChildItem $root -ErrorAction Stop)) {
                Set-ItemProperty -Path $key.PSPath -Name 'NetbiosOptions' -Value $value -Type DWord `
                                 -ErrorAction Stop
            }
        }

        'guest-account' {
            $guest = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }
            if ($guest) {
                if ($on) { $guest | Enable-LocalUser } else { $guest | Disable-LocalUser }
            }
        }
    }
}
catch {
    Write-Error "Could not turn $Toggle $State. $($_.Exception.Message)"
    exit 1
}

@{ toggle = $Toggle; state = $State } | ConvertTo-Json -Compress
