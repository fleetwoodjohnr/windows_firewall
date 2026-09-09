<#
.SYNOPSIS
  Builds win-harden.exe, win-harden-broker.exe, and the installer.

  Two executables rather than one, because they need different manifests: the
  GUI is asInvoker and the broker is requireAdministrator. That difference is
  the entire elevation design, so it is enforced here at build time rather than
  being left to how someone happens to launch them.
#>
[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipInstaller
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }

try {
    Write-Step "Cleaning previous output"
    foreach ($dir in 'build','dist') {
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    }

    $common = @(
        '--noconfirm', '--clean',
        '--distpath', 'dist',
        '--workpath', 'build',
        '--specpath', 'build',
        # The scripts are read at runtime from beside the exe, so they ship as
        # data rather than being frozen in.
        '--add-data', "scripts\ps;scripts\ps"
    )

    Write-Step "Building the GUI (asInvoker)"
    & $Python -m PyInstaller @common `
        --name 'win-harden' `
        --windowed `
        --manifest 'installer\app.manifest' `
        --icon 'installer\win-harden.ico' `
        --collect-submodules win_harden `
        --collect-submodules broker `
        'win-harden.py'
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed building the GUI" }

    Write-Step "Building the broker (requireAdministrator)"
    & $Python -m PyInstaller @common `
        --name 'win-harden-broker' `
        --console `
        --manifest 'installer\broker.manifest' `
        --collect-submodules broker `
        --exclude-module PySide6 `
        'win-harden-broker.py'
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed building the broker" }

    # The GUI locates the broker beside its own executable (broker_path() in
    # backend/broker_client.py), so the two one-folder builds are merged.
    Write-Step "Merging the broker into the app folder"
    Copy-Item 'dist\win-harden-broker\*' 'dist\win-harden\' -Recurse -Force
    Remove-Item 'dist\win-harden-broker' -Recurse -Force

    foreach ($exe in 'win-harden.exe','win-harden-broker.exe') {
        $path = "dist\win-harden\$exe"
        if (-not (Test-Path $path)) { throw "$exe was not produced" }
        Write-Host ("  {0,-26} {1:N1} MB" -f $exe, ((Get-Item $path).Length / 1MB))
    }
    if (-not (Test-Path 'dist\win-harden\scripts\ps\set-toggle.ps1')) {
        throw "The PowerShell scripts were not bundled; the app would be unable to change anything."
    }

    if ($SkipInstaller) {
        Write-Step "Done (installer skipped)"
        Write-Host "Run it from dist\win-harden\win-harden.exe"
        return
    }

    Write-Step "Building the installer"
    $iscc = @(
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        Write-Warning "Inno Setup was not found, so no installer was built. The app in dist\win-harden is complete and runnable."
        return
    }
    & $iscc 'installer\win-harden.iss'
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

    $setup = Get-ChildItem 'installer\Output\*.exe' | Select-Object -First 1
    Write-Step "Done"
    Write-Host "Installer: $($setup.FullName)" -ForegroundColor Green
}
finally { Pop-Location }
