<#
.SYNOPSIS
  Pins one interface's resolver, or returns it to the network's own.

  The caller sends a provider ID and never an address. The addresses live in the
  table below, on the privileged side, so a compromised GUI process cannot point
  the machine's DNS at a server of its choosing. broker/dns_providers.py holds
  the same table for display, and tests/test_ps_scripts.py asserts the two agree.

  Registering the DoH template before setting the servers is not optional: an
  interface pointed at a resolver Windows has no template for falls back to
  plaintext, which looks like it worked and is not encrypted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{1,10}$')][string]$InterfaceIndex,
    [Parameter(Mandatory)][ValidateSet('automatic','quad9','cloudflare','mullvad','adguard')]
    [string]$Provider
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$PROVIDERS = @{
    'quad9'      = @{ v4 = @('9.9.9.9','149.112.112.112')
                      v6 = @('2620:fe::fe','2620:fe::9')
                      template = 'https://dns.quad9.net/dns-query' }
    'cloudflare' = @{ v4 = @('1.1.1.1','1.0.0.1')
                      v6 = @('2606:4700:4700::1111','2606:4700:4700::1001')
                      template = 'https://cloudflare-dns.com/dns-query' }
    'mullvad'    = @{ v4 = @('194.242.2.2')
                      v6 = @('2a07:e340::2')
                      template = 'https://dns.mullvad.net/dns-query' }
    'adguard'    = @{ v4 = @('94.140.14.14','94.140.15.15')
                      v6 = @('2a10:50c0::ad1:ff','2a10:50c0::ad2:ff')
                      template = 'https://dns.adguard-dns.com/dns-query' }
}

$index = [int]$InterfaceIndex

try {
    if ($Provider -eq 'automatic') {
        # ResetServerAddresses returns the interface to DHCP-supplied DNS. The
        # DoH registrations are machine-wide and are left in place: removing them
        # would un-encrypt any other interface still using the same resolver.
        Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses
        @{ interfaceIndex = $index; provider = 'automatic'; pinned = $false } |
            ConvertTo-Json -Compress
        exit 0
    }

    $p = $PROVIDERS[$Provider]

    foreach ($addr in ($p.v4 + $p.v6)) {
        $existing = Get-DnsClientDohServerAddress -ServerAddress $addr -ErrorAction SilentlyContinue
        if ($existing) {
            Set-DnsClientDohServerAddress -ServerAddress $addr -DohTemplate $p.template `
                -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
        } else {
            Add-DnsClientDohServerAddress -ServerAddress $addr -DohTemplate $p.template `
                -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
        }
    }

    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @($p.v4 + $p.v6)
    $actual = @((Get-DnsClientServerAddress -InterfaceIndex $index).ServerAddresses)
    foreach ($address in $p.v4) { if ($address -notin $actual) { throw 'Windows did not apply the requested DNS servers.' } }

    Clear-DnsClientCache
    @{ interfaceIndex = $index; provider = $Provider; pinned = $true;
       servers = $p.v4; template = $p.template } | ConvertTo-Json -Depth 4 -Compress
}
catch {
    Write-Error "Could not set the resolver on interface $index to $Provider. $($_.Exception.Message)"
    exit 1
}
