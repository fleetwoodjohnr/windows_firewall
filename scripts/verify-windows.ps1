<# Run against an installed build. -RunScan adds a harmless file scan through the service. #>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'win-harden'),
    [string]$Report = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'win-harden-verification.json'),
    [switch]$RunScan,
    [switch]$SyntaxOnly
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$checks = New-Object System.Collections.Generic.List[object]
function Test-Check {
    param([string]$Name, [scriptblock]$Body)
    try { $detail = & $Body; $checks.Add(@{name=$Name; passed=$true; detail=$detail}); Write-Host "PASS $Name" }
    catch { $checks.Add(@{name=$Name; passed=$false; detail=$_.Exception.Message}); Write-Host "FAIL $Name : $_" }
}
function Request-Scanner {
    param([hashtable]$Request)
    $Request.version = 1
    $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'WinHardenScanner-v1', [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        $pipe.Connect(5000)
        $serverPid = [uint32]0
        if (-not [WinHardenPipePeer]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$serverPid)) { throw 'Cannot verify pipe server.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='WinHardenScanner'"
        if (-not $serverPid -or $serverPid -ne $service.ProcessId) { throw 'Unexpected scan service process.' }
        $writer = New-Object IO.StreamWriter($pipe, (New-Object Text.UTF8Encoding($false)), 4096, $true)
        $writer.AutoFlush = $true
        $writer.WriteLine(($Request | ConvertTo-Json -Compress))
        $reader = New-Object IO.StreamReader($pipe)
        $pending = $reader.ReadLineAsync()
        if (-not $pending.Wait(70000)) { throw 'Service response timed out.' }
        if (-not $pending.Result -or $pending.Result.Length -gt 262144) { throw 'Invalid service response size.' }
        $response = $pending.Result | ConvertFrom-Json
        if ($response.version -ne 1 -or -not $response.ok) { throw "Service refused request: $($response.error)" }
        return $response.result
    } finally { $pipe.Dispose() }
}
if ($SyntaxOnly) { $source = Split-Path -Parent $PSScriptRoot }
else { $source = $InstallDir }
Test-Check 'PowerShell syntax' {
    $files = @(Get-ChildItem -LiteralPath $source -Filter '*.ps1' -Recurse |
        Where-Object { $_.FullName -notmatch '[\\/]\.venv' })
    if (-not $files.Count) { throw 'No packaged PowerShell scripts found.' }
    foreach ($file in $files) {
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw "$($file.FullName): $($errors.Message -join '; ')" }
    }
    "$($files.Count) scripts parsed using PowerShell $($PSVersionTable.PSVersion)"
}
if (-not $SyntaxOnly) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class WinHardenPipePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle, out uint pid);
}
'@
    Test-Check 'Windows 11 x64' {
        $os = Get-CimInstance Win32_OperatingSystem
        if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000 -or
            $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or -not [Environment]::Is64BitProcess) {
            throw 'Requires a Windows 11 Intel/AMD x64 desktop and 64-bit PowerShell.'
        }
        "$($os.Caption), build $($os.BuildNumber)"
    }
    Test-Check 'Bundled runtime' {
        foreach ($name in @('win-harden','win-harden-broker','win-harden-scanner')) {
            $path = Join-Path $InstallDir "$name.exe"
            if (-not (Test-Path -LiteralPath $path)) { throw "Missing $path" }
            $process = Start-Process -FilePath $path -ArgumentList '--self-test' -WorkingDirectory $env:TEMP -PassThru
            if (-not $process.WaitForExit(120000)) { $process.Kill(); throw "$name startup timed out." }
            if ($process.ExitCode -ne 0) { throw "$name self-test failed: $($process.ExitCode)" }
        }
        'All three executables started outside the source tree.'
    }
    Test-Check 'Scan service' {
        $s = Get-CimInstance Win32_Service -Filter "Name='WinHardenScanner'"
        if ($s.State -ne 'Running' -or $s.StartMode -ne 'Auto' -or $s.StartName -ne 'LocalSystem') { throw 'Service is not running with the expected configuration.' }
        $s.PathName
    }
    Test-Check 'Defender health through service' {
        $health = Request-Scanner @{op='health'}
        if (-not $health.available -or -not $health.realtimeProtection -or -not $health.downloadProtection) {
            throw 'Defender or its real-time/download protection is unavailable or disabled. Open Windows Security.'
        }
        $health
    }
    Test-Check 'Sign-in monitor shortcut' {
        $shortcut = Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'WinHarden download monitor.lnk'
        if (-not (Test-Path -LiteralPath $shortcut)) { throw 'The sign-in shortcut is missing.' }
        $shortcut
    }
    if ($RunScan) {
        Test-Check 'Harmless file scan through service' {
            $path = Join-Path $env:TEMP ('win-harden-check-' + [guid]::NewGuid().ToString() + '.txt')
            try {
                'Harmless Windows Firewall and Hardening scan verification.' | Set-Content -LiteralPath $path
                $job = Request-Scanner @{op='submit'; kind='custom'; path=$path; request_id=[guid]::NewGuid().ToString()}
                $deadline = (Get-Date).AddMinutes(5)
                while ($job.state -in @('queued','running')) {
                    if ((Get-Date) -gt $deadline) { throw 'Scan still pending after five minutes; review Recent scans.' }
                    Start-Sleep -Seconds 2
                    $job = Request-Scanner @{op='job'; job_id=$job.id}
                }
                if ($job.state -ne 'clean') { throw "Scan result: $($job.state). $($job.result.message)" }
                $job
            } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    }
}
@{ generated=(Get-Date).ToUniversalTime().ToString('o'); checks=@($checks.ToArray()) } |
    ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Report -Encoding UTF8
Write-Host "Report: $Report"
if (@($checks | Where-Object { -not $_.passed }).Count) { exit 1 }
exit 0
