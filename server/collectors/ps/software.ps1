# Ares - installed software collector (read-only)
# Reads the per-machine and per-user uninstall registry keys. No file or network access.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$maxItems = 1200

function Read-UninstallKey {
  param([string]$Path, [string]$Scope, [string]$Hive)

  $items = @()
  $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
  if (-not $key) { return $items }

  foreach ($name in @($key.GetSubKeyNames())) {
    $sub = $null
    try { $sub = $key.OpenSubKey($name) } catch { continue }
    if (-not $sub) { continue }
    try {
      $displayName = [string]$sub.GetValue('DisplayName')
      if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
      if ($sub.GetValue('SystemComponent') -eq 1) { continue }
      if ($sub.GetValue('ReleaseType') -eq 'Update') { continue }
      if ($sub.GetValue('ParentKeyName')) { continue }

      $version = [string]$sub.GetValue('DisplayVersion')
      $items += [pscustomobject]@{
        name        = $displayName.Trim()
        version     = if ([string]::IsNullOrWhiteSpace($version)) { $null } else { $version.Trim() }
        publisher   = [string]$sub.GetValue('Publisher')
        scope       = $Scope
        hive        = $Hive
        installDate = [string]$sub.GetValue('InstallDate')
      }
    }
    catch { }
    finally { $sub.Close() }
  }
  return $items
}

try {
  $software = @()
  $software += Read-UninstallKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Scope 'machine' -Hive 'HKLM'
  $software += Read-UninstallKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Scope 'machine' -Hive 'HKLM-WOW6432'
  $software += Read-UninstallKey -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Scope 'user' -Hive 'HKCU'

  $total = $software.Count
  if ($total -gt $maxItems) {
    $software = @($software | Select-Object -First $maxItems)
  }

  # Preserve enough identity for version comparison but drop install paths (not needed and may contain usernames).
  $clean = @()
  foreach ($s in $software) {
    $clean += [pscustomobject]@{
      name        = $s.name
      version     = $s.version
      publisher   = if ([string]::IsNullOrWhiteSpace($s.publisher)) { $null } else { $s.publisher.Trim() }
      scope       = $s.scope
      installDate = if ([string]::IsNullOrWhiteSpace($s.installDate)) { $null } else { $s.installDate }
    }
  }

  $payload = [ordered]@{
    collectedAt = (Get-Date).ToString('o')
    source      = 'Windows uninstall registry (HKLM, HKLM WOW6432Node, HKCU)'
    truncated   = ($total -gt $maxItems)
    totalFound  = $total
    software    = $clean
  }

  $json = ConvertTo-Json -InputObject $payload -Compress -Depth 6
}
catch {
  $json = ConvertTo-Json -InputObject @{ __collectorError = $_.Exception.Message } -Compress
}

Write-Output ('@@ARES@@' + $json)
