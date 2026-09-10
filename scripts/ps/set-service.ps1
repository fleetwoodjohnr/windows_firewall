[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('RemoteRegistry','WinRM','TermService','sshd')][string]$ServiceName,
    [Parameter(Mandatory)][ValidateSet('Automatic','Manual','Disabled','AutomaticDelayedStart')][string]$StartupType,
    [Parameter(Mandatory)][ValidateSet('on','off')][string]$State
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $type = if ($StartupType -eq 'AutomaticDelayedStart') { 'Automatic' } else { $StartupType }
    if ($State -eq 'off') { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
    Set-Service -Name $ServiceName -StartupType $type
    # The service name is a closed enum; this cannot address an arbitrary key.
    # DelayedAutoStart is deliberately preserved; Set-Service only changes Start.
    if ($State -eq 'on') { Start-Service -Name $ServiceName -ErrorAction Stop }
    $s = Get-Service -Name $ServiceName
    if ([string]$s.StartType -ne $type -or (($s.Status -eq 'Running') -ne ($State -eq 'on'))) { throw 'The service did not reach the requested state.' }
    @{ service=$ServiceName; startupType=$StartupType; running=($s.Status -eq 'Running') } | ConvertTo-Json -Compress
} catch { Write-Error $_.Exception.Message; exit 1 }
