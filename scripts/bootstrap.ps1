<#
.SYNOPSIS
  One command to go from a clean Windows 11 machine to a built installer.

  This is where "download any and all important dependencies" happens. Everything
  the build needs is fetched here, once, on the machine doing the building --
  so that the installer it produces needs nothing at all at install time.

  That split is deliberate. An installer that downloads dependencies has a dozen
  ways to fail on someone else's machine: no internet, a proxy, a pinned TLS
  version, a package that moved. The end user gets a single self-contained exe
  instead, and all of that risk is absorbed here.

.EXAMPLE
  .\scripts\bootstrap.ps1
  .\scripts\bootstrap.ps1 -SkipInstaller     # build the exes, skip Inno Setup
#>
[CmdletBinding()]
param(
    [switch]$SkipInstaller,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Test-Command { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

Write-Step "Checking Windows version"
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt 22000) {
    Write-Warning "This looks like Windows 10 (build $build). The app targets Windows 11; some settings (native DoH in particular) will not be available."
}

Write-Step "Checking for winget"
if (-not (Test-Command 'winget')) {
    Write-Error @"
winget is not available, so dependencies cannot be installed automatically.

Install 'App Installer' from the Microsoft Store, then run this again. Or install
these by hand and re-run:
  - Python 3.11 or newer   https://www.python.org/downloads/
  - Inno Setup 6           https://jrsoftware.org/isdl.php
"@
    exit 1
}

Write-Step "Installing Python"
if (-not (Test-Command 'py')) {
    winget install --id Python.Python.3.13 --exact --silent --accept-package-agreements --accept-source-agreements
    # winget updates PATH for new processes, not this one.
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path','User')
}
if (-not (Test-Command 'py')) { Write-Error "Python still isn't on PATH. Open a new terminal and run this again."; exit 1 }
py -3 --version

if (-not $SkipInstaller) {
    Write-Step "Installing Inno Setup"
    $iscc = Get-ChildItem 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe','C:\Program Files\Inno Setup 6\ISCC.exe' -ErrorAction SilentlyContinue
    if (-not $iscc) {
        winget install --id JRSoftware.InnoSetup --exact --silent --accept-package-agreements --accept-source-agreements
    }
}

Write-Step "Creating the build virtual environment"
$venv = Join-Path $repo '.venv-build'
if (-not (Test-Path $venv)) { py -3 -m venv $venv }
$python = Join-Path $venv 'Scripts\python.exe'

Write-Step "Installing Python dependencies"
& $python -m pip install --upgrade pip --quiet
& $python -m pip install --quiet `
    PySide6 `
    pywin32 `
    pyinstaller `
    pytest
Write-Host "  PySide6      the GUI toolkit"
Write-Host "  pywin32      named pipes, security descriptors, ShellExecute"
Write-Host "  pyinstaller  bundles CPython and Qt into the exe"
Write-Host "  pytest       runs the test suite below"

# pywin32 installs COM/service DLLs that need registering before use.
& $python -c "import pywin32_bootstrap" 2>$null
$postinstall = Join-Path $venv 'Scripts\pywin32_postinstall.py'
if (Test-Path $postinstall) { & $python $postinstall -install -silent | Out-Null }

if (-not $SkipTests) {
    Write-Step "Running the test suite"
    Push-Location $repo
    try {
        & $python -m pytest tests -q
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Tests failed. Not building an installer from a failing tree."
            exit 1
        }
    } finally { Pop-Location }
}

Write-Step "Building"
& (Join-Path $PSScriptRoot 'build.ps1') -Python $python -SkipInstaller:$SkipInstaller
