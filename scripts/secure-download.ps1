# Shared by bootstrap and optional extras. Dot-source from shipped scripts only.
$ErrorActionPreference = 'Stop'

function Assert-DefenderReady {
    $s = Get-MpComputerStatus -ErrorAction Stop
    if (-not $s.AMServiceEnabled -or -not $s.AntivirusEnabled -or -not $s.AntivirusSignatureVersion) {
        throw 'Microsoft Defender must be available to verify downloaded dependencies. Nothing downloaded will be executed.'
    }
}

function Assert-ScannedFile {
    param([Parameter(Mandatory)][string]$Path)
    Assert-DefenderReady
    $scanScript = Join-Path $script:SecurityRoot 'scanner\ps\operation.ps1'
    $before = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $raw = & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scanScript -Operation custom -LiteralPath $Path
    if ($LASTEXITCODE -ne 0) { throw "Defender failed to scan $Path" }
    $result = ($raw -join "`n") | ConvertFrom-Json
    if ($result.error -or $result.exitCode -ne 0 -or -not $result.scanCompleted -or $result.excluded -or @($result.threats).Count) {
        $reason = if ($result.error) { [string]$result.error }
            elseif ($result.excluded) { 'The file is excluded from Microsoft Defender scanning. Review ExclusionPath and archive scanning settings.' }
            elseif (@($result.threats).Count) { 'Microsoft Defender reported a threat. Review Windows Security.' }
            elseif ($result.exitCode -ne 0) { "Microsoft Defender exited with code $($result.exitCode)." }
            else { 'Microsoft Defender did not provide a matching scan-completion event.' }
        Write-Host ('Defender verification result: ' + ($result | ConvertTo-Json -Depth 6 -Compress))
        throw "Download was not verified clean: $Path. $reason"
    }
    if (-not (Test-Path -LiteralPath $Path) -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $before) {
        throw 'The download changed during scanning. It will not be executed.'
    }
}

function Get-VerifiedDownload {
    param([Parameter(Mandatory)]$Package, [Parameter(Mandatory)][string]$Destination)
    $uri = [uri]$Package.url
    if ($uri.Scheme -ne 'https' -or $uri.Host -notin @('www.python.org','github.com','download.sysinternals.com') -or
        $Package.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid pinned download manifest.' }
    Assert-DefenderReady
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $partial = $Destination + '.partial'
    Invoke-WebRequest -Uri $uri.AbsoluteUri -OutFile $partial -UseBasicParsing -MaximumRedirection 5
    if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $Package.sha256) {
        throw 'Download checksum mismatch. The vendor may have published a different version; update the reviewed manifest.'
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
    if ($Package.publisher) {
        $sig = Get-AuthenticodeSignature -LiteralPath $Destination
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch $Package.publisher) {
            throw "The expected publisher signature could not be verified for $Destination"
        }
    }
    Assert-ScannedFile -Path $Destination
    return $Destination
}

function Invoke-CheckedNative {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$FilePath failed with exit code $LASTEXITCODE" }
}

function Initialize-PrivateDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $node = [IO.DirectoryInfo]$Path
    while ($null -ne $node) {
        if ($node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Staging cannot contain reparse points.' }
        $node = $node.Parent
    }
    if (Test-Path -LiteralPath $Path) {
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Staging has an untrusted owner. Repair ownership before continuing.' }
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
