<# One command on Windows 11 x64: download, verify, scan, install build dependencies, test, package. #>
[CmdletBinding()]
param([switch]$SkipInstaller, [switch]$SkipTests, [string]$BuildPython)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$script:SecurityRoot = $repo
. (Join-Path $PSScriptRoot 'secure-download.ps1')
if (-not [Environment]::Is64BitProcess -or [Environment]::OSVersion.Version.Build -lt 22000 -or
    $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Run 64-bit Windows PowerShell on Windows 11 Intel/AMD x64.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator, then run scripts\bootstrap.ps1. Defender scanning and dependency installation require elevation.'
}
Write-Host 'Checking Microsoft Defender before downloading build dependencies...'
Assert-DefenderReady
try { Update-MpSignature -ErrorAction Stop } catch { Write-Warning "Definition update failed; using installed definitions: $_" }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'downloads.json') -Raw | ConvertFrom-Json
$work = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'win-harden-build'
Initialize-PrivateDirectory -Path $work

$pythonHome = Join-Path $work 'Python313'
$basePython = Join-Path $pythonHome 'python.exe'
if ($BuildPython) {
    if (-not (Test-Path -LiteralPath $BuildPython -PathType Leaf)) {
        throw "The selected build Python does not exist: $BuildPython"
    }
    $basePython = (Resolve-Path -LiteralPath $BuildPython).Path
    Write-Host "Using the selected build Python: $basePython"
} elseif (-not (Test-Path -LiteralPath $basePython)) {
    Write-Host 'Downloading and verifying the pinned Python installer...'
    $installer = Get-VerifiedDownload -Package $manifest.python -Destination (Join-Path $work 'python-setup.exe')
    $pythonInstallLog = Join-Path $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $work }) 'python-install.log'
    $arguments = @('/quiet','InstallAllUsers=1',"TargetDir=$pythonHome",'Include_launcher=0',
        'Include_test=0','PrependPath=0','Include_pip=1','/log',$pythonInstallLog)
    $process = Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0,3010)) { throw "Python setup failed: $($process.ExitCode). Log: $pythonInstallLog" }
    if (-not (Test-Path -LiteralPath $basePython -PathType Leaf)) {
        throw "Python setup exited successfully but did not create $basePython. An existing installation of the same Python version may have entered maintenance mode. Log: $pythonInstallLog"
    }
}
$expectedPython = [string]$manifest.python.version
$checkPython = "import sys,struct; expected=tuple(map(int,sys.argv[1].split('.'))); assert sys.version_info[:3] == expected and struct.calcsize('P') == 8, 'Expected Python %s x64, got %s' % (sys.argv[1], sys.version.split()[0])"
Invoke-CheckedNative $basePython @('-c',$checkPython,$expectedPython)
$venv = Join-Path $repo '.venv-build'
if (-not (Test-Path -LiteralPath (Join-Path $venv 'Scripts\python.exe'))) { Invoke-CheckedNative $basePython @('-m','venv',$venv) }
$python = Join-Path $venv 'Scripts\python.exe'
Invoke-CheckedNative $python @('-c',$checkPython,$expectedPython)
Write-Host 'Downloading and verifying pinned dependency wheels...'
$wheels = Join-Path $work 'wheels'
New-Item -ItemType Directory -Path $wheels -Force | Out-Null
$lock = Join-Path $repo 'requirements-win.lock'
Invoke-CheckedNative $python @('-m','pip','download','--index-url','https://pypi.org/simple','--require-hashes','--only-binary=:all:','--dest',$wheels,'-r',$lock)
foreach ($wheel in Get-ChildItem -LiteralPath $wheels -Filter '*.whl') { Assert-ScannedFile -Path $wheel.FullName }
Invoke-CheckedNative $python @('-m','pip','install','--no-index','--find-links',$wheels,'--require-hashes','-r',$lock)
Invoke-CheckedNative $python @('-m','pip','check')
# pywin32 postinstall is intentionally not used in a virtual environment.

$iscc = Join-Path $work 'InnoSetup\ISCC.exe'
if (-not $SkipInstaller -and -not (Test-Path -LiteralPath $iscc)) {
    Write-Host 'Downloading and verifying the pinned Inno Setup installer...'
    $installer = Get-VerifiedDownload -Package $manifest.inno -Destination (Join-Path $work 'inno-setup.exe')
    $target = Split-Path -Parent $iscc
    $process = Start-Process $installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/ALLUSERS',"/DIR=`"$target`"") -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Inno Setup failed: $($process.ExitCode)" }
}
Push-Location $repo
try {
    if (-not $SkipTests) {
        Write-Host 'Running application tests...'
        & $python -m pytest tests -q
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Not building an installer from a failing tree.' }
    }
    Write-Host 'Building and verifying the frozen application and installer...'
    & (Join-Path $PSScriptRoot 'build.ps1') -Python $python -Iscc $iscc -SkipInstaller:$SkipInstaller
} finally { Pop-Location }
