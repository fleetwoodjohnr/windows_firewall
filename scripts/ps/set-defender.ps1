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
                 'realtimeMonitoring')]
    [string]$Setting,

    [Parameter(Mandatory)]
    [ValidateSet('Disabled','Basic','Advanced','AlwaysPrompt','SendSafeSamples','NeverSend',
                 'SendAllSamples','Default','Moderate','High','HighPlus','ZeroTolerance',
                 'Enabled','AuditMode','0','10','20','30','40','50','True','False')]
    [string]$Value
)
$ErrorActionPreference = 'Stop'

try {
    switch ($Setting) {
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
}
catch {
    Write-Error "Could not set $Setting to $Value. $($_.Exception.Message)"
    exit 1
}

@{ setting = $Setting; value = $Value } | ConvertTo-Json -Compress
