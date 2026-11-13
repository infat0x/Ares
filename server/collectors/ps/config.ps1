# Ares - security configuration collector (read-only)
# Observes local security settings only. It changes nothing and reads no user documents.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$checks = New-Object System.Collections.ArrayList

function Add-Check {
  param(
    [string]$Id,
    [string]$Category,
    [string]$Status,
    $Observed,
    [string]$Detail
  )
  [void]$checks.Add([pscustomobject]@{
    id       = $Id
    category = $Category
    status   = $Status
    observed = $Observed
    detail   = $Detail
  })
}

function New-Unknown {
  param([string]$Reason)
  return [pscustomobject]@{ unknownReason = $Reason }
}

# --- Windows Firewall -------------------------------------------------------
try {
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
  $list = @()
  $disabled = @()
  foreach ($p in $profiles) {
    $list += [pscustomobject]@{ name = [string]$p.Name; enabled = [bool]$p.Enabled }
    if (-not $p.Enabled) { $disabled += [string]$p.Name }
  }
  $status = if ($disabled.Count -gt 0) { 'weak' } else { 'ok' }
  Add-Check -Id 'firewall' -Category 'network' -Status $status -Observed ([pscustomobject]@{ profiles = $list; disabledProfiles = $disabled }) -Detail ''
}
catch {
  Add-Check -Id 'firewall' -Category 'network' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-NetFirewallProfile failed'
}

# --- Microsoft Defender ----------------------------------------------------
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $realTime = [bool]$mp.RealTimeProtectionEnabled
  $status = if ($realTime) { 'ok' } else { 'weak' }
  $signatureAge = $null
  if ($mp.AntivirusSignatureAge -ne $null) { $signatureAge = [int]$mp.AntivirusSignatureAge }
  Add-Check -Id 'defender' -Category 'endpoint' -Status $status -Observed ([pscustomobject]@{
    available           = $true
    realTimeProtection  = $realTime
    antivirusEnabled    = [bool]$mp.AntivirusEnabled
    tamperProtection    = [bool]$mp.IsTamperProtected
    signatureAgeDays    = $signatureAge
  }) -Detail ''
}
catch {
  Add-Check -Id 'defender' -Category 'endpoint' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-MpComputerStatus failed (Defender may be replaced by another product)'
}

# --- SMBv1 -----------------------------------------------------------------
try {
  $smb = Get-SmbServerConfiguration -ErrorAction Stop
  $enabled = [bool]$smb.EnableSMB1Protocol
  Add-Check -Id 'smb1' -Category 'network' -Status $(if ($enabled) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    enabled      = $enabled
    signingRequired = [bool]$smb.RequireSecuritySignature
    smb2Enabled  = [bool]$smb.EnableSMB2Protocol
  }) -Detail ''
}
catch {
  Add-Check -Id 'smb1' -Category 'network' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-SmbServerConfiguration failed; run as administrator for SMB state'
}

# --- Remote Desktop -------------------------------------------------------
try {
  $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
  $rdpEnabled = ([int]$ts.fDenyTSConnections -eq 0)
  $nla = $null
  $rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
  if ($rdpTcp -and $null -ne $rdpTcp.UserAuthentication) { $nla = ([int]$rdpTcp.UserAuthentication -eq 1) }
  Add-Check -Id 'rdp' -Category 'remote-access' -Status 'info' -Observed ([pscustomobject]@{
    enabled     = $rdpEnabled
    nlaRequired = $nla
  }) -Detail ''
}
catch {
  Add-Check -Id 'rdp' -Category 'remote-access' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Could not read Terminal Server registry values'
}

# --- Local Guest account --------------------------------------------------
try {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
  $enabled = [bool]$guest.Enabled
  Add-Check -Id 'guestAccount' -Category 'accounts' -Status $(if ($enabled) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    enabled = $enabled
  }) -Detail ''
}
catch {
  Add-Check -Id 'guestAccount' -Category 'accounts' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-LocalUser failed'
}

# --- LLMNR ----------------------------------------------------------------
try {
  $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
  $enabled = $true
  if ($policy -and $null -ne $policy.EnableMulticast) { $enabled = ([int]$policy.EnableMulticast -ne 0) }
  Add-Check -Id 'llmnr' -Category 'network' -Status $(if ($enabled) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    enabled = $enabled
    source  = if ($policy -and $null -ne $policy.EnableMulticast) { 'policy' } else { 'default' }
  }) -Detail ''
}
catch {
  Add-Check -Id 'llmnr' -Category 'network' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail ''
}

# --- WinRM listeners ------------------------------------------------------
try {
  $listeners = @()
  foreach ($l in @(Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue)) {
    $transport = $null
    $address = $null
    try { $transport = [string](Get-ItemProperty "$($l.PSPath)\Transport" -ErrorAction SilentlyContinue).Value } catch { }
    try { $address = [string](Get-ItemProperty "$($l.PSPath)\Port" -ErrorAction SilentlyContinue).Value } catch { }
    $listeners += [pscustomobject]@{ transport = $transport; port = $address }
  }
  Add-Check -Id 'winrm' -Category 'remote-access' -Status 'info' -Observed ([pscustomobject]@{
    listenerCount = $listeners.Count
    listeners     = $listeners
    httpListeners = @($listeners | Where-Object { $_.transport -eq 'HTTP' }).Count
  }) -Detail ''
}
catch {
  Add-Check -Id 'winrm' -Category 'remote-access' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'WSMan provider unavailable'
}

# --- UAC ------------------------------------------------------------------
try {
  $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
  $enableLua = $null
  if ($null -ne $uac.EnableLUA) { $enableLua = ([int]$uac.EnableLUA -eq 1) }
  $tokenFilter = $null
  if ($null -ne $uac.LocalAccountTokenFilterPolicy) { $tokenFilter = ([int]$uac.LocalAccountTokenFilterPolicy -eq 1) }
  $status = if ($enableLua -eq $false) { 'weak' } else { 'ok' }
  Add-Check -Id 'uac' -Category 'accounts' -Status $status -Observed ([pscustomobject]@{
    enabled                   = $enableLua
    adminConsentPrompt        = if ($null -ne $uac.ConsentPromptBehaviorAdmin) { [int]$uac.ConsentPromptBehaviorAdmin } else { $null }
    localAccountTokenFilter   = $tokenFilter
  }) -Detail ''
}
catch {
  Add-Check -Id 'uac' -Category 'accounts' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail ''
}

# --- PowerShell v2 engine ------------------------------------------------
try {
  $feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction Stop
  $installed = ([string]$feature.State -eq 'Enabled')
  Add-Check -Id 'powershellV2' -Category 'hardening' -Status $(if ($installed) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    installed = $installed
  }) -Detail ''
}
catch {
  Add-Check -Id 'powershellV2' -Category 'hardening' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-WindowsOptionalFeature requires elevation'
}

# --- Secure Boot ---------------------------------------------------------
try {
  $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
  Add-Check -Id 'secureBoot' -Category 'hardening' -Status $(if ($secureBoot) { 'ok' } else { 'weak' }) -Observed ([pscustomobject]@{
    enabled = [bool]$secureBoot
  }) -Detail ''
}
catch {
  Add-Check -Id 'secureBoot' -Category 'hardening' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Confirm-SecureBootUEFI requires elevation and UEFI firmware'
}

# --- BitLocker -----------------------------------------------------------
try {
  $systemDrive = $env:SystemDrive
  $volume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop
  $protection = [string]$volume.ProtectionStatus
  Add-Check -Id 'bitlocker' -Category 'data-protection' -Status $(if ($protection -eq 'On') { 'ok' } else { 'weak' }) -Observed ([pscustomobject]@{
    mountPoint       = $systemDrive
    protectionStatus = $protection
    encryptionPercentage = if ($null -ne $volume.EncryptionPercentage) { [int]$volume.EncryptionPercentage } else { $null }
  }) -Detail ''
}
catch {
  Add-Check -Id 'bitlocker' -Category 'data-protection' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Get-BitLockerVolume requires elevation'
}

# --- Unquoted service paths ---------------------------------------------
try {
  $suspicious = @()
  $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
  foreach ($svc in $services) {
    $path = [string]$svc.PathName
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    if ($path.StartsWith('"')) { continue }
    $exeIndex = $path.ToLowerInvariant().IndexOf('.exe')
    if ($exeIndex -lt 0) { continue }
    $exePart = $path.Substring(0, $exeIndex)
    if ($exePart.Contains(' ')) {
      $suspicious += [pscustomobject]@{ name = [string]$svc.Name; startMode = [string]$svc.StartMode }
    }
  }
  Add-Check -Id 'unquotedServices' -Category 'hardening' -Status $(if ($suspicious.Count -gt 0) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    count   = $suspicious.Count
    samples = @($suspicious | Select-Object -First 10)
  }) -Detail ''
}
catch {
  Add-Check -Id 'unquotedServices' -Category 'hardening' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail 'Win32_Service enumeration failed'
}

# --- Autologon (boolean only; credentials are never read) ----------------
try {
  $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
  $hasUser = -not [string]::IsNullOrWhiteSpace([string]$winlogon.DefaultUserName)
  $hasPassword = -not [string]::IsNullOrWhiteSpace([string]$winlogon.DefaultPassword)
  $autoAdmin = ($null -ne $winlogon.AutoAdminLogon -and [int]$winlogon.AutoAdminLogon -eq 1)
  $enabled = ($autoAdmin -or ($hasUser -and $hasPassword))
  Add-Check -Id 'autologon' -Category 'accounts' -Status $(if ($enabled) { 'weak' } else { 'ok' }) -Observed ([pscustomobject]@{
    enabled        = $enabled
    credentialStored = $hasPassword
  }) -Detail 'No usernames or passwords are read into the report'
}
catch {
  Add-Check -Id 'autologon' -Category 'accounts' -Status 'unknown' -Observed (New-Unknown $_.Exception.Message) -Detail ''
}

$payload = [ordered]@{
  collectedAt = (Get-Date).ToString('o')
  checks      = @($checks)
}
$json = ConvertTo-Json -InputObject $payload -Compress -Depth 8
Write-Output ('@@ARES@@' + $json)
