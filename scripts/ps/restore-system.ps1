[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('firewall','netbios','guest','dns')][string]$Resource,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9+/=]{1,65536}$')][string]$Data
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $value = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Data)) | ConvertFrom-Json
    switch ($Resource) {
        'firewall' {
            foreach ($p in @($value | Where-Object { $null -ne $_ })) {
                if ($p.name -notin @('Domain','Private','Public') -or $p.enabled -notin @('True','False','NotConfigured') -or
                    $p.inbound -notin @('Allow','Block','NotConfigured') -or $p.outbound -notin @('Allow','Block','NotConfigured')) { throw 'Invalid firewall snapshot' }
                Set-NetFirewallProfile -Profile $p.name -Enabled $p.enabled -DefaultInboundAction $p.inbound -DefaultOutboundAction $p.outbound
            }
        }
        'netbios' {
            foreach ($p in @($value | Where-Object { $null -ne $_ })) {
                if ($p.name -notmatch '^Tcpip_\{[0-9a-fA-F-]{36}\}$' -or ($p.exists -and $p.value -notin @(0,1,2))) { throw 'Invalid NetBIOS snapshot' }
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $p.name
                if (-not (Test-Path -LiteralPath $key)) { throw 'An original network interface is no longer present; restoration retained for retry.' }
                if ($p.exists) { Set-ItemProperty -LiteralPath $key -Name NetbiosOptions -Type DWord -Value ([int]$p.value) }
                else { Remove-ItemProperty -LiteralPath $key -Name NetbiosOptions -ErrorAction SilentlyContinue }
            }
        }
        'guest' {
            foreach ($p in @($value | Where-Object { $null -ne $_ })) {
                if ($p.sid -notmatch '^S-1-5-21-\d+-\d+-\d+-501$' -or $p.enabled -isnot [bool]) { throw 'Invalid Guest account snapshot' }
                $user = Get-LocalUser -SID $p.sid
                if ($p.enabled) { $user | Enable-LocalUser } else { $user | Disable-LocalUser }
            }
        }
        'dns' {
            foreach ($a in @($value.adapters | Where-Object { $null -ne $_ })) {
                $guid = [guid]$a.guid
                $adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq $guid }
                if (-not $adapter) { throw "Original DNS adapter $guid is not present; retry when it returns." }
                foreach ($f in @($a.families)) {
                    if ($f.family -notin @('IPv4','IPv6') -or $f.automatic -isnot [bool]) { throw 'Invalid DNS snapshot' }
                    $target = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $f.family
                    if ($f.automatic) { $target | Set-DnsClientServerAddress -ResetServerAddresses }
                    else {
                        foreach ($s in @($f.servers)) { $parsed = [ipaddress]::Parse($s) }
                        $target | Set-DnsClientServerAddress -ServerAddresses @($f.servers)
                    }
                }
            }
            foreach ($p in @($value.doh | Where-Object { $null -ne $_ })) {
                $ip = [ipaddress]::Parse($p.address)
                $uri = [uri]$p.template
                if ($uri.Scheme -ne 'https' -or $p.upgrade -isnot [bool] -or $p.fallback -isnot [bool]) { throw 'Invalid DoH snapshot' }
                $existing = Get-DnsClientDohServerAddress -ServerAddress $p.address -ErrorAction SilentlyContinue
                if ($existing) { Set-DnsClientDohServerAddress -ServerAddress $p.address -DohTemplate $p.template -AutoUpgrade $p.upgrade -AllowFallbackToUdp $p.fallback }
                else { Add-DnsClientDohServerAddress -ServerAddress $p.address -DohTemplate $p.template -AutoUpgrade $p.upgrade -AllowFallbackToUdp $p.fallback }
            }
            foreach ($address in @($value.removeDoh | Where-Object { $null -ne $_ })) {
                $ip = [ipaddress]::Parse($address)
                if (Get-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue) {
                    Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction Stop
                }
            }
        }
    }
    @{ restored=$Resource } | ConvertTo-Json -Compress
} catch { Write-Error $_.Exception.Message; exit 1 }
