[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('quick','full','custom','update','remediate','protect')][string]$Operation,
    [string]$LiteralPath
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ProgressPreference = 'SilentlyContinue'
$logName = 'Microsoft-Windows-Windows Defender/Operational'

function Get-DefenderExecutable {
    $platform = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows Defender\Platform'
    $candidates = @(Get-ChildItem -LiteralPath $platform -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+-\d+$' } |
        Sort-Object { [version]($_.Name.Split('-')[0]) } -Descending |
        ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' })
    $candidates += Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Windows Defender\MpCmdRun.exe'
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $sig = Get-AuthenticodeSignature -LiteralPath $candidate
            if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)') {
                return $candidate
            }
        }
    }
    throw 'A valid Microsoft-signed Defender executable could not be located.'
}

try {
    if ($Operation -eq 'update') {
        Update-MpSignature -ErrorAction Stop
        $s = Get-MpComputerStatus
        @{ state='completed'; message='Defender definitions updated.'; signatureVersion=[string]$s.AntivirusSignatureVersion;
           signatureAgeDays=[int]$s.AntivirusSignatureAge } | ConvertTo-Json -Depth 5 -Compress
        exit 0
    }
    if ($Operation -eq 'protect') {
        # Never disable Tamper Protection or replace an organization's policy.
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableIOAVProtection $false
        $s = Get-MpComputerStatus
        $p = Get-MpPreference
        if (-not $s.RealTimeProtectionEnabled -or $p.DisableIOAVProtection) {
            throw 'Windows did not enable both protection settings. Open Windows Security or contact your administrator.'
        }
        @{ state='completed'; message='Real-time and downloaded-file protection are enabled.' } | ConvertTo-Json -Compress
        exit 0
    }
    if ($Operation -eq 'remediate') {
        Remove-MpThreat -ErrorAction Stop
        $remaining = @((Get-MpThreat -ErrorAction Stop) | Where-Object { $_.IsActive })
        $state = if ($remaining.Count) { 'action_required' } else { 'remediated' }
        @{ state=$state; message="Active threats remaining: $($remaining.Count). Review Windows Security for details." } |
            ConvertTo-Json -Compress
        exit 0
    }

    $mp = Get-DefenderExecutable
    $argsList = @('-Scan', '-ScanType', $(switch ($Operation) { 'quick' { '1' } 'full' { '2' } 'custom' { '3' } }))
    if ($Operation -eq 'custom') {
        if ($LiteralPath -notmatch '^[A-Za-z]:[\\/]' -or $LiteralPath.Substring(2) -match '[:*?"\x00-\x1F]' -or
            $LiteralPath.Length -gt 240 -or -not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
            throw 'The custom scan target must be an existing local file.'
        }
        # Repeat reparse validation at use time, including all parent folders.
        $item = Get-Item -LiteralPath $LiteralPath -Force
        while ($null -ne $item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked scan paths are refused.' }
            $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
        }
        $excludeOutput = & $mp -CheckExclusion -Path $LiteralPath 2>&1
        $excludeCode = $LASTEXITCODE
        # Documented HRESULT S_OK means excluded; S_FALSE means not excluded.
        if ($excludeCode -eq 0) {
            @{ excluded=$true; exitCode=0; scanCompleted=$false; threats=@() } | ConvertTo-Json -Depth 5 -Compress
            exit 0
        }
        if ($excludeCode -ne 1) { throw "Unable to verify Defender exclusions (code $excludeCode)." }
        $preferences = Get-MpPreference -ErrorAction Stop
        if ($preferences.DisableArchiveScanning -and [IO.Path]::GetExtension($LiteralPath) -in @('.zip','.whl','.7z','.rar','.cab','.tar','.gz','.iso')) {
            @{ excluded=$true; exitCode=0; scanCompleted=$false; threats=@(); error='Archive scanning is disabled in Microsoft Defender.' } | ConvertTo-Json -Compress
            exit 0
        }
        $argsList += @('-File', $LiteralPath)
    }

    $started = Get-Date
    $watermark = (Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop).RecordId
    $output = & $mp @argsList 2>&1
    $code = $LASTEXITCODE
    $completed = Get-Date
    # MpCmdRun returns as soon as the service answers, but MsMpEng writes the
    # start and finish records to the channel afterwards. Reading the log once
    # raced that flush and reported a completed scan as unverified, so wait for
    # the pair instead. A healthy machine matches on the first pass.
    $deadline = (Get-Date).AddSeconds(60)
    $verified = $false
    $attribution = 'none'
    $seenEvents = 0
    $seenStarts = 0
    $seenMatched = 0
    $seenEnds = 0
    do {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName=$logName; Id=@(1000,1001,1002); StartTime=$started.AddSeconds(-1) } -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordId -gt $watermark })
        $starts = @{}
        $ends = @{}
        $anyStarts = @{}
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
            $id = $data['Scan ID']
            if ($id) {
                if ($event.Id -eq 1000) {
                    # Resource data is present for custom scans. Without it, do not
                    # attribute a concurrent Windows scan to the requested file.
                    $anyStarts[$id] = $true
                    $resource = ([string]$data['Scan Resources']).Trim()
                    $matchesFile = $resource -eq $LiteralPath -or $resource -eq "file:_$LiteralPath" -or $resource -eq "containerfile:_$LiteralPath"
                    if ($Operation -ne 'custom' -or $matchesFile) { $starts[$id] = $true }
                }
                if ($event.Id -eq 1001) { $ends[$id] = $true }
            }
        }
        $seenEvents = $events.Count
        $seenStarts = $anyStarts.Count
        $seenMatched = $starts.Count
        $seenEnds = $ends.Count
        # At least one, not exactly one: real-time protection scans the file as it
        # is written, so a second completed pair is expected and is not a fault.
        if (@($starts.Keys | Where-Object { $ends.ContainsKey($_) }).Count -ge 1) {
            $verified = $true
            $attribution = 'resource'
            break
        }
        # Only when nothing matched by resource. The watermark is taken immediately
        # before the scan, so a single new pair inside that window is this scan.
        if (@($anyStarts.Keys | Where-Object { $ends.ContainsKey($_) }).Count -eq 1) {
            $verified = $true
            $attribution = 'window'
            break
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    # Counts only, so a system scan can never disclose another user's file paths.
    $evidence = @{ events=$seenEvents; scanStarts=$seenStarts; resourceMatched=$seenMatched;
                   scanFinishes=$seenEnds; attribution=$attribution }
    if ($Operation -eq 'custom') {
        $text = ([string]($output | Out-String)).Trim() -replace '\s+', ' '
        if ($text.Length -gt 500) { $text = $text.Substring(0, 500) }
        $evidence['output'] = $text
    }
    $active = @{}
    foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $active[[string]$t.ThreatID] = $t }
    $threats = @()
    foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) {
        if ($d.InitialDetectionTime -lt $started -and $d.LastThreatStatusChangeTime -lt $started) { continue }
        $resources = @($d.Resources | ForEach-Object { [string]$_ })
        if ($Operation -eq 'custom' -and -not @($resources | Where-Object {
            $_ -eq $LiteralPath -or $_ -eq "file:_$LiteralPath" -or $_ -eq "containerfile:_$LiteralPath"
        }).Count) { continue }
        $t = $active[[string]$d.ThreatID]
        $threats += @{ id=[string]$d.ThreatID; name=[string]$t.ThreatName;
            active=($null -eq $t -or [bool]$t.IsActive); actionSuccess=[bool]$d.ActionSuccess;
            # System scans expose threat names, never other users' file paths.
            resource=$(if ($Operation -eq 'custom') { $LiteralPath } else { 'See Windows Security' }) }
    }
    @{ exitCode=$code; scanCompleted=$verified; threats=@($threats | Select-Object -First 30);
       scanEvidence=$evidence;
       started=$started.ToUniversalTime().ToString('o'); finished=$completed.ToUniversalTime().ToString('o') } |
        ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ error=$_.Exception.Message; state='failed'; message=$_.Exception.Message } | ConvertTo-Json -Compress
    exit 0
}
