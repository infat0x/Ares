# Ares - Windows update collector (read-only)
# Reports installed hotfixes and update configuration visible to the current user.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$errors = @()
$hotfixes = @()
$hotfixSource = 'Win32_QuickFixEngineering'

try {
  $qfes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop)
  foreach ($q in $qfes) {
    $installed = $null
    if ($q.InstalledOn) {
      try { $installed = ([datetime]$q.InstalledOn).ToString('o') } catch { $installed = [string]$q.InstalledOn }
    }
    $hotfixes += [pscustomobject]@{
      id          = [string]$q.HotFixID
      description = [string]$q.Description
      installedOn = $installed
      source      = $hotfixSource
    }
  }
}
catch {
  $errors += "Win32_QuickFixEngineering: $($_.Exception.Message)"
  $hotfixSource = 'Get-HotFix'
  try {
    foreach ($h in @(Get-HotFix -ErrorAction Stop)) {
      $installed = $null
      if ($h.InstalledOn) {
        try { $installed = ([datetime]$h.InstalledOn).ToString('o') } catch { $installed = [string]$h.InstalledOn }
      }
      $hotfixes += [pscustomobject]@{
        id          = [string]$h.HotFixID
        description = [string]$h.Description
        installedOn = $installed
        source      = 'Get-HotFix'
      }
    }
  }
  catch {
    $errors += "Get-HotFix: $($_.Exception.Message)"
  }
}

$hotfixes = @($hotfixes | Sort-Object -Property installedOn -Descending)
if ($hotfixes.Count -gt 300) { $hotfixes = @($hotfixes | Select-Object -First 300) }

$autoUpdate = @{
  noAutoUpdate = $null
  auOptions    = $null
  wsusServer   = $null
}
try {
  $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
  if ($au) {
    if ($null -ne $au.NoAutoUpdate) { $autoUpdate.noAutoUpdate = [int]$au.NoAutoUpdate }
    if ($null -ne $au.AUOptions) { $autoUpdate.auOptions = [int]$au.AUOptions }
  }
  $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
  if ($wu -and $wu.WUServer) { $autoUpdate.wsusServer = [string]$wu.WUServer }
}
catch { $errors += "WindowsUpdate policy: $($_.Exception.Message)" }

$results = @{ lastSearchSuccess = $null; lastInstallSuccess = $null }
try {
  $detect = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -ErrorAction SilentlyContinue
  if ($detect -and $detect.LastSuccessTime) { $results.lastSearchSuccess = [string]$detect.LastSuccessTime }
  $install = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -ErrorAction SilentlyContinue
  if ($install -and $install.LastSuccessTime) { $results.lastInstallSuccess = [string]$install.LastSuccessTime }
}
catch { $errors += "WindowsUpdate results: $($_.Exception.Message)" }

$pendingReboot = $false
try {
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReboot = $true }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
}
catch { }

$serviceStatus = $null
try {
  $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if ($svc) { $serviceStatus = [string]$svc.Status }
}
catch { }

$payload = [ordered]@{
  collectedAt   = (Get-Date).ToString('o')
  source        = 'Win32_QuickFixEngineering via CIM'
  hotfixSource  = $hotfixSource
  hotfixes      = $hotfixes
  hotfixCount   = $hotfixes.Count
  updateService = [ordered]@{
    name   = 'wuauserv'
    status = $serviceStatus
  }
  policy            = $autoUpdate
  lastSearchSuccess = $results.lastSearchSuccess
  lastInstallSuccess = $results.lastInstallSuccess
  pendingReboot     = $pendingReboot
  errors            = $errors
}

$json = ConvertTo-Json -InputObject $payload -Compress -Depth 6
Write-Output ('@@ARES@@' + $json)
