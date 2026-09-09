<#
.SYNOPSIS
  Optional security tooling, installed only when explicitly asked for.

  Each of these is a checkbox in the installer, unticked by default, and each is
  reversible. None of them is needed for the app itself to work.

  Three rules govern what this script is willing to do automatically, and the
  difference between them is deliberate:

    * Downloads come from a fixed list of vendor URLs written into this file.
      Nothing is fetched from a URL supplied by anyone.
    * Tools that only OBSERVE are installed and started. Sysmon writes to an
      event log and blocks nothing, so the worst case of getting it wrong is
      wasted disk.
    * Tools that ENFORCE are downloaded and left for you to apply by hand.
      Microsoft's Windows 11 security baseline is roughly three thousand policy
      settings written straight into Group Policy with no undo, and applying it
      unattended to a personal machine is how someone loses access to their own
      computer. It is fetched, unpacked, and explained -- and that is where this
      script stops.

.EXAMPLE
  .\extras.ps1 -DefenderSignatures
  .\extras.ps1 -Sysmon
  .\extras.ps1 -SecurityBaseline
#>
[CmdletBinding()]
param(
    [switch]$DefenderSignatures,
    [switch]$Sysmon,
    [switch]$SecurityBaseline,
    [switch]$RemoveSysmon
)
$ErrorActionPreference = 'Stop'

# Fixed vendor URLs. Nothing here is ever composed from input.
$URLS = @{
    Sysmon       = 'https://download.sysinternals.com/files/Sysmon.zip'
    SysmonConfig = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
    Toolkit      = 'https://www.microsoft.com/en-us/download/details.aspx?id=55319'
}

$WorkDir = Join-Path $env:ProgramData 'win-harden\extras'
function Write-Step { param([string]$M) Write-Host "`n==> $M" -ForegroundColor Cyan }

function Get-File {
    param([string]$Uri, [string]$OutFile)
    Write-Host "  downloading $Uri"
    # TLS 1.2 explicitly: this script may run on a machine whose defaults this
    # very app has just tightened, and an unset protocol here would fail
    # confusingly.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    $hash = (Get-FileHash $OutFile -Algorithm SHA256).Hash
    Write-Host "  SHA256 $hash"
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# -- Defender signatures ------------------------------------------------------

if ($DefenderSignatures) {
    Write-Step "Updating Microsoft Defender signatures"
    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (-not (Test-Path $mp)) {
        Write-Warning "MpCmdRun.exe was not found. Defender may be replaced by another antivirus."
    } else {
        & $mp -SignatureUpdate
        try {
            $status = Get-MpComputerStatus
            Write-Host "  signatures now $($status.AntivirusSignatureVersion), $($status.AntivirusSignatureAge) day(s) old"
        } catch { }
    }
}

# -- Sysmon -------------------------------------------------------------------

if ($Sysmon) {
    Write-Step "Installing Sysmon"
    Write-Host @"
  Sysmon records what happens on this PC -- every process started and by what,
  every network connection and which program made it, driver loads, and changes
  to registry keys that matter. It blocks nothing. Its value is entirely after
  the fact: when something does go wrong, the difference between guessing and
  knowing is whether this was running beforehand.

  Events land in the Windows event log under
  Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.
"@
    $zip = Join-Path $WorkDir 'Sysmon.zip'
    $dir = Join-Path $WorkDir 'Sysmon'
    Get-File -Uri $URLS.Sysmon -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    $exe = Join-Path $dir 'Sysmon64.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path $dir 'Sysmon.exe' }
    if (-not (Test-Path $exe)) { Write-Error "Sysmon was not found in the downloaded archive."; exit 1 }

    # Microsoft signs Sysmon. Refuse to run an unsigned binary that arrived over
    # the network, whatever the URL said.
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne 'Valid') {
        Write-Error "The downloaded Sysmon is not validly signed (status: $($sig.Status)). Refusing to run it."
        exit 1
    }
    Write-Host "  signed by: $($sig.SignerCertificate.Subject)"

    $config = Join-Path $WorkDir 'sysmonconfig.xml'
    try {
        Get-File -Uri $URLS.SysmonConfig -OutFile $config
        Write-Host "  configuration: SwiftOnSecurity/sysmon-config (MIT), the community default"
    } catch {
        Write-Warning "The configuration could not be downloaded; installing with Sysmon's own defaults, which log considerably more noise."
        $config = $null
    }

    if ($config) { & $exe -accepteula -i $config } else { & $exe -accepteula -i }
    Write-Host "  Sysmon is running. Remove it with: extras.ps1 -RemoveSysmon"
}

if ($RemoveSysmon) {
    Write-Step "Removing Sysmon"
    $exe = Join-Path $WorkDir 'Sysmon\Sysmon64.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path $WorkDir 'Sysmon\Sysmon.exe' }
    if (Test-Path $exe) { & $exe -u } else { Write-Warning "Sysmon was not found; nothing to remove." }
}

# -- Security baseline --------------------------------------------------------

if ($SecurityBaseline) {
    Write-Step "Microsoft Security Compliance Toolkit"
    Write-Host @"
  The Security Compliance Toolkit contains Microsoft's own Windows 11 security
  baseline -- around three thousand Group Policy settings -- along with LGPO.exe
  for applying them.

  This script does NOT apply it, and that is a deliberate choice rather than an
  omission. The baseline is written for managed corporate fleets with a help
  desk. On a personal machine it can disable Microsoft accounts, enforce a
  password policy on an account that had none, restrict removable storage, and
  turn off features you use daily -- and LGPO has no undo. Applying three
  thousand settings unattended to someone's only computer is not hardening, it
  is an outage.

  The hardening levels in this app cover the settings that matter most for a
  desktop, each one individually explained and individually reversible. Use the
  baseline if you specifically want Microsoft's full corporate posture and are
  prepared to read it first.

  Download it from:
    $($URLS.Toolkit)

  Then, having read the spreadsheets in the Documentation folder:
    LGPO.exe /g "<baseline>\GPOs"
"@
    Start-Process $URLS.Toolkit
}

if (-not ($DefenderSignatures -or $Sysmon -or $SecurityBaseline -or $RemoveSysmon)) {
    Write-Host "Nothing selected. Pass -DefenderSignatures, -Sysmon, or -SecurityBaseline."
}
