[CmdletBinding()]
param([switch]$DefenderSignatures, [switch]$Sysmon, [switch]$SecurityBaseline, [switch]$RemoveSysmon)
$ErrorActionPreference = 'Stop'
$script:SecurityRoot = Join-Path (Split-Path -Parent $PSScriptRoot) '_internal'
if (-not (Test-Path -LiteralPath $script:SecurityRoot)) { $script:SecurityRoot = Split-Path -Parent $PSScriptRoot }
. (Join-Path $PSScriptRoot 'secure-download.ps1')
$work = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'win-harden\extras'
Initialize-PrivateDirectory -Path $work
if ($DefenderSignatures) { Update-MpSignature -ErrorAction Stop }
if ($Sysmon) {
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'downloads.json') -Raw | ConvertFrom-Json
    $zip = Get-VerifiedDownload $manifest.sysmon (Join-Path $work 'Sysmon.zip')
    $dir = Join-Path $work 'Sysmon'
    Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
    foreach ($file in Get-ChildItem -LiteralPath $dir -File -Recurse) { Assert-ScannedFile -Path $file.FullName }
    $exe = Join-Path $dir 'Sysmon64.exe'
    $sig = Get-AuthenticodeSignature -LiteralPath $exe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
        throw 'Refusing to run it: Sysmon is not validly signed by Microsoft.'
    }
    Invoke-CheckedNative $exe @('-accepteula','-i')
    Write-Host 'Sysmon installed with its vendor defaults. Use -RemoveSysmon to remove it.'
}
if ($RemoveSysmon) {
    $exe = Join-Path $work 'Sysmon\Sysmon64.exe'
    if (Test-Path -LiteralPath $exe) {
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw 'Invalid Sysmon publisher signature.' }
        Invoke-CheckedNative $exe @('-u')
    }
}
if ($SecurityBaseline) {
    # This opens documentation; it does NOT apply it. LGPO.exe /g would apply
    # policies outside this app's reversible settings.
    Start-Process 'https://www.microsoft.com/en-us/download/details.aspx?id=55319'
}
