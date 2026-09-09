<#
.SYNOPSIS
  Reads network adapters, their category, and their DNS configuration.
  Unprivileged, changes nothing.
#>
$ErrorActionPreference = 'Stop'

$out = [ordered]@{}

try {
    $doh = @{}
    # DoH server registrations are machine-wide, keyed by resolver address.
    try {
        foreach ($d in Get-DnsClientDohServerAddress -ErrorAction Stop) {
            $doh[[string]$d.ServerAddress] = [ordered]@{
                template    = [string]$d.DohTemplate
                autoUpgrade = [bool]$d.AutoUpgrade
                udpFallback = [bool]$d.AllowFallbackToUdp
            }
        }
    } catch { }

    $interfaces = @()
    foreach ($a in (Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                    Where-Object { $_.Status -ne 'Not Present' })) {
        $servers = @()
        try {
            $servers = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex `
                          -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
        } catch { }

        $category = $null
        try {
            $category = [string](Get-NetConnectionProfile -InterfaceIndex $a.ifIndex `
                                 -ErrorAction Stop).NetworkCategory
        } catch { }

        $interfaces += [ordered]@{
            index       = [int]$a.ifIndex
            name        = [string]$a.Name
            description = [string]$a.InterfaceDescription
            status      = [string]$a.Status
            category    = $category
            dnsServers  = $servers
            # An interface is encrypted only if every resolver it uses is
            # registered for DoH. One plaintext resolver in the list means
            # lookups can still leave in clear.
            dohEnabled  = ($servers.Count -gt 0) -and
                          (@($servers | Where-Object { $doh.ContainsKey($_) }).Count -eq $servers.Count)
        }
    }
    $out.interfaces = $interfaces
    $out.dohServers = $doh
}
catch {
    $out.error = "Network configuration could not be read: $($_.Exception.Message)"
}

$out | ConvertTo-Json -Depth 6 -Compress
