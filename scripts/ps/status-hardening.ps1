<#
.SYNOPSIS
  Reads exploit mitigations and BitLocker status. Unprivileged, changes nothing.

  recoveryKeySaved is the guard rail for the Exploit family's Strict level. This
  app never switches BitLocker on, and refuses Strict entirely while any
  protected volume has no recovery password saved -- because a firmware update
  or TPM change on a machine whose key exists nowhere means every file on the
  drive is gone permanently.
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$out = [ordered]@{}

$mitigations = [ordered]@{}
try {
    $m = Get-ProcessMitigation -System -ErrorAction Stop
    # 'ON'/'OFF'/'NOTSET' come back as enum values; compare as strings so a
    # NOTSET is reported as not-enabled rather than crashing a bool cast.
    $mitigations['dep']              = ([string]$m.Dep.Enable)
    $mitigations['aslr-bottomup']    = ([string]$m.Aslr.BottomUp)
    $mitigations['aslr-highentropy'] = ([string]$m.Aslr.HighEntropy)
    $mitigations['aslr-force']       = ([string]$m.Aslr.ForceRelocateImages)
    $mitigations['sehop']            = ([string]$m.SEHOP.Enable)
    $mitigations['cfg']              = ([string]$m.CFG.Enable)
}
catch {
    $out.mitigationsError = "Exploit protection could not be read: $($_.Exception.Message)"
}
$out.mitigations = $mitigations

$volumes = @()
try {
    foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
        $hasRecoveryPassword = @($v.KeyProtector |
            Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
        $volumes += [ordered]@{
            mountPoint       = [string]$v.MountPoint
            protectionOn     = ([string]$v.ProtectionStatus -eq 'On')
            encryptionMethod = [string]$v.EncryptionMethod
            percentEncrypted = [int]$v.EncryptionPercentage
            # A recovery password protector existing is what makes the volume
            # recoverable. Whether the user also wrote it down is not something
            # Windows can tell us, and this app does not pretend otherwise.
            recoveryProtectorPresent = $hasRecoveryPassword
        }
    }
}
catch {
    # No BitLocker (Home edition, or no TPM) is a legitimate answer.
    $out.bitlockerError = $_.Exception.Message
}
$out.bitlocker = $volumes

try {
    $raw = (Get-MpPreference).EnableControlledFolderAccess
    $names = @{0='Disabled';1='Enabled';2='AuditMode';3='BlockDiskModificationOnly';4='AuditDiskModificationOnly'}
    $out.controlledFolderAccess = $names[[int]$raw]
} catch { $out.controlledFolderAccess = $null }

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
          -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
    $out.deviceGuard = [ordered]@{
        vbsRunning       = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2)
        credentialGuard  = (@($dg.SecurityServicesRunning) -contains 1)
        hvci             = (@($dg.SecurityServicesRunning) -contains 2)
    }
} catch { $out.deviceGuard = $null }

$out | ConvertTo-Json -Depth 6 -Compress
