[CmdletBinding()]
param([string]$Python = 'python', [string]$Iscc, [switch]$SkipInstaller)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Build on Windows x64.' }
    & $Python -c "import struct,sys; assert struct.calcsize('P') == 8 and sys.platform == 'win32'"
    if ($LASTEXITCODE) { throw 'The build Python must target Windows x64.' }
    $version = (& $Python win_harden\version.py).Trim()
    if ($LASTEXITCODE -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid application version.' }
    & $Python scripts\make-icon.py
    if ($LASTEXITCODE) { throw 'Icon generation failed.' }
    & $Python scripts\version-info.py
    if ($LASTEXITCODE) { throw 'Windows version resource generation failed.' }
    & $Python -m PyInstaller --noconfirm --clean installer\win-harden.spec
    if ($LASTEXITCODE) { throw 'PyInstaller failed.' }
    foreach ($path in @('win-harden.exe','win-harden-broker.exe','win-harden-scanner.exe',
                        '_internal\scripts\ps\set-toggle.ps1','_internal\win_harden\style.qss',
                        '_internal\scanner\ps\operation.ps1','_internal\scanner\ps\status.ps1')) {
        if (-not (Test-Path -LiteralPath "dist\win-harden\$path")) { throw "Missing bundled resource: $path" }
    }
    & $Python scripts\verify-package.py dist\win-harden
    if ($LASTEXITCODE) { throw 'Frozen package validation failed.' }
    & $Python -m pip list --format=json | Set-Content dist\win-harden\dependencies.json -Encoding UTF8
    if ($LASTEXITCODE) { throw 'Could not record build dependencies.' }
    if ($SkipInstaller) { return }
    if (-not $Iscc) {
        $Iscc = @('C:\Program Files (x86)\Inno Setup 6\ISCC.exe','C:\Program Files\Inno Setup 6\ISCC.exe') |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $Iscc -or -not (Test-Path -LiteralPath $Iscc)) { throw 'Inno Setup is missing. Run scripts\bootstrap.ps1.' }
    & $Iscc "/DAppVersion=$version" installer\win-harden.iss
    if ($LASTEXITCODE) { throw 'Inno Setup failed.' }
    $setup = Get-Item "installer\Output\WinHardenSetup-$version.exe"
    $script:SecurityRoot = $repo
    . (Join-Path $PSScriptRoot 'secure-download.ps1')
    Assert-ScannedFile -Path $setup.FullName
    $hash = (Get-FileHash -LiteralPath $setup.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($setup.Name)" | Set-Content ($setup.FullName + '.sha256') -Encoding ASCII
    Write-Host "Installer: $($setup.FullName)"
} finally { Pop-Location }
