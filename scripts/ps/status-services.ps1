<#
.SYNOPSIS
  Reads the services and optional features the app can switch, plus whether an
  SSH key is installed. Unprivileged, changes nothing.

  sshAuthorizedKeyPresent is the Windows descendant of the Fedora helper's
  find_ssh_key_owner(): password authentication is never disabled unless a
  usable key already exists, so switching SSH hardening on cannot lock anyone
  out of a machine they only reach over the network.
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$out = [ordered]@{}

$watched = @('RemoteRegistry','WinRM','TermService','sshd','WinHttpAutoProxySvc','LanmanServer')
$services = @()
$out.serviceErrors = @{}
$out.featureErrors = @{}
foreach ($name in $watched) {
    try {
        $s = Get-Service -Name $name -ErrorAction Stop
        $services += [ordered]@{
            name      = [string]$s.Name
            display   = [string]$s.DisplayName
            running   = ($s.Status -eq 'Running')
            startType = [string]$s.StartType
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoServiceFoundForGivenName*') { $out.serviceErrors[$name] = $_.Exception.Message }
    }
}
$out.services = $services

$features = @()
foreach ($name in @('SMB1Protocol')) {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
        $features += [ordered]@{ name = [string]$f.FeatureName; enabled = ($f.State -eq 'Enabled') }
    } catch { $out.featureErrors[$name] = $_.Exception.Message }
}
$out.features = $features

try {
    $c = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop |
         Select-Object -First 1
    $out.opensshServer = [ordered]@{
        name      = [string]$c.Name
        installed = ($c.State -eq 'Installed')
    }
} catch { $out.opensshServer = $null }

# An SSH key counts if it is in the administrators' key file or in any real
# user's profile. Non-empty and containing at least one non-comment line.
$keyFound = $false
$candidates = @("$env:ProgramData\ssh\administrators_authorized_keys")
try {
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop)) {
        $candidates += (Join-Path $p.FullName '.ssh\authorized_keys')
    }
} catch { }
foreach ($path in $candidates) {
    try {
        if (Test-Path $path) {
            $lines = Get-Content $path -ErrorAction Stop |
                     Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
            if ($lines) { $keyFound = $true; break }
        }
    } catch { }
}
$out.sshAuthorizedKeyPresent = $keyFound

try { $out.guestAccountEnabled = [bool](Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1).Enabled }
catch { $out.guestAccountEnabled = $null }

$out | ConvertTo-Json -Depth 5 -Compress
