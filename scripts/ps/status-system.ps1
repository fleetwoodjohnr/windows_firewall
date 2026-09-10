[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('firewall','netbios','guest','dns')][string]$Resource)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $value = switch ($Resource) {
        'firewall' {
            @(Get-NetFirewallProfile | ForEach-Object { @{ name=[string]$_.Name; enabled=[string]$_.Enabled;
                inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction } })
        }
        'netbios' {
            $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            @(Get-ChildItem -LiteralPath $root | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath
                @{ name=$_.PSChildName; exists=($null -ne $p.NetbiosOptions); value=$p.NetbiosOptions }
            })
        }
        'guest' {
            @(Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | ForEach-Object {
                @{ sid=$_.SID.Value; enabled=[bool]$_.Enabled }
            })
        }
        'dns' {
            $adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
                $a = $_
                $families = @()
                foreach ($af in @('IPv4','IPv6')) {
                    $service = if ($af -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
                    $id = '{' + ([guid]$a.InterfaceGuid).ToString() + '}'
                    $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$service\Parameters\Interfaces\$id"
                    $saved = Get-ItemProperty -LiteralPath $reg -ErrorAction SilentlyContinue
                    $families += @{ family=$af; automatic=[string]::IsNullOrWhiteSpace([string]$saved.NameServer);
                        servers=@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily $af).ServerAddresses) }
                }
                @{ guid=[string]$a.InterfaceGuid; index=[int]$a.ifIndex; families=$families }
            })
            $doh = @(Get-DnsClientDohServerAddress | ForEach-Object { @{ address=[string]$_.ServerAddress;
                template=[string]$_.DohTemplate; upgrade=[bool]$_.AutoUpgrade; fallback=[bool]$_.AllowFallbackToUdp } })
            @{ adapters=$adapters; doh=$doh }
        }
    }
    @{ value=$value } | ConvertTo-Json -Depth 8 -Compress
} catch { Write-Error $_.Exception.Message; exit 1 }
