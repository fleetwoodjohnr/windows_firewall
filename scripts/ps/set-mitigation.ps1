<#
.SYNOPSIS
  Turns one system-wide exploit mitigation on or off.

  aslr-force is mandatory ASLR. It is the one mitigation here that reliably
  breaks real, current software -- programs not built to be relocated simply
  fail to start, usually with no useful error. It is offered only at Strict and
  the level copy says so plainly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('dep','aslr-bottomup','aslr-highentropy','aslr-force','sehop','cfg')]
    [string]$Mitigation,

    [Parameter(Mandatory)]
    [ValidateSet('on','off')]
    [string]$State,
    [ValidateSet('yes','no')][string]$Reset = 'no'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$name = switch ($Mitigation) {
    'dep'              { 'DEP' }
    'aslr-bottomup'    { 'BottomUp' }
    'aslr-highentropy' { 'HighEntropy' }
    'aslr-force'       { 'ForceRelocateImages' }
    'sehop'            { 'SEHOP' }
    'cfg'              { 'CFG' }
}

try {
    if ($Reset -eq 'yes') {
        Set-ProcessMitigation -System -Remove -Disable $name
    } elseif ($State -eq 'on') {
        Set-ProcessMitigation -System -Enable $name
    } else {
        Set-ProcessMitigation -System -Disable $name
    }
}
catch {
    Write-Error "Could not set mitigation $name to $State. $($_.Exception.Message)"
    exit 1
}

@{ mitigation = $Mitigation; state = $State } | ConvertTo-Json -Compress
