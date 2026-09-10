<#
.SYNOPSIS
  Sets one Microsoft Defender preference.

  One setting per call, both the name and the value drawn from closed sets. That
  is what lets the broker journal a prior value and restore it later through
  exactly this same path -- a restore is just another validated call, never a
  blob of saved state being splatted back into an elevated process.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('mapsReporting','submitSamples','cloudBlockLevel','puaProtection',
                 'controlledFolderAccess','networkProtection','cloudExtendedTimeout',
                 'realtimeMonitoring','ioavProtection')]
    [string]$Setting,

    [Parameter(Mandatory)]
    [ValidateSet('Disabled','Basic','Advanced','AlwaysPrompt','SendSafeSamples','NeverSend',
                 'SendAllSamples','Default','Moderate','High','HighPlus','ZeroTolerance',
                 'Enabled','AuditMode','BlockDiskModificationOnly','AuditDiskModificationOnly','0','10','20','30','40','50','True','False')]
    [string]$Value
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

try {
    switch ($Setting) {
        'ioavProtection'         { Set-MpPreference -DisableIOAVProtection (-not [bool]::Parse($Value)) }
        'mapsReporting'          { Set-MpPreference -MAPSReporting $Value }
        'submitSamples'          { Set-MpPreference -SubmitSamplesConsent $Value }
        'cloudBlockLevel'        { Set-MpPreference -CloudBlockLevel $Value }
        'cloudExtendedTimeout'   { Set-MpPreference -CloudExtendedTimeout ([uint32]$Value) }
        'puaProtection'          { Set-MpPreference -PUAProtection $Value }
        'controlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess $Value }
        'networkProtection'      { Set-MpPreference -EnableNetworkProtection $Value }
        'realtimeMonitoring'     {
            # Expressed as a positive elsewhere in the app; Defender's own
            # parameter is the negative. Never used to turn protection OFF: the
            # only caller is a restore putting back what was there before.
            Set-MpPreference -DisableRealtimeMonitoring:([bool]::Parse($Value) -eq $false)
        }
    }
    $properties = @{ mapsReporting='MAPSReporting'; submitSamples='SubmitSamplesConsent'; cloudBlockLevel='CloudBlockLevel';
        puaProtection='PUAProtection'; controlledFolderAccess='EnableControlledFolderAccess'; networkProtection='EnableNetworkProtection';
        cloudExtendedTimeout='CloudExtendedTimeout'; realtimeMonitoring='DisableRealtimeMonitoring'; ioavProtection='DisableIOAVProtection' }
    $current = (Get-MpPreference).($properties[$Setting])
    if ($Setting -in @('realtimeMonitoring','ioavProtection')) {
        if ((-not [bool]$current) -ne [bool]::Parse($Value)) { throw 'Windows refused the requested protection setting.' }
    } else {
        $numeric = @{ Disabled=0; Basic=1; Advanced=2; AlwaysPrompt=0; SendSafeSamples=1; NeverSend=2; SendAllSamples=3;
            Default=0; Moderate=1; High=2; HighPlus=4; ZeroTolerance=6; Enabled=1; AuditMode=2; BlockDiskModificationOnly=3; AuditDiskModificationOnly=4 }
        $expected = if ($numeric.ContainsKey($Value)) { $numeric[$Value] } else { [int]$Value }
        if ([int]$current -ne $expected) { throw 'Windows policy or Tamper Protection prevented this preference change.' }
    }
}
catch {
    Write-Error "Could not set $Setting to $Value. $($_.Exception.Message)"
    exit 1
}

@{ setting = $Setting; value = $Value } | ConvertTo-Json -Compress
