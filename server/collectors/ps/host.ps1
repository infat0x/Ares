# Ares - host collector (read-only)
# Emits host identity, Windows build and local IP addresses.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
  $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
  $tz = Get-TimeZone -ErrorAction SilentlyContinue

  $buildNumber = $null
  if ($os.BuildNumber) { $buildNumber = [string]$os.BuildNumber }
  if ($cv.CurrentBuildNumber) { $buildNumber = [string]$cv.CurrentBuildNumber }

  $ubr = $null
  if ($null -ne $cv.UBR) { $ubr = [int]$cv.UBR }

  $build = $buildNumber
  if ($buildNumber -and $null -ne $ubr) { $build = "$buildNumber.$ubr" }

  $chassis = @()
  if ($enclosure -and $enclosure.ChassisTypes) { $chassis = @($enclosure.ChassisTypes | ForEach-Object { [int]$_ }) }

  $addresses = @()
  $net = @(Get-NetIPAddress -ErrorAction SilentlyContinue)
  foreach ($ip in $net) {
    $addr = [string]$ip.IPAddress
    if (-not $addr) { continue }
    if ($addr -like '169.254.*') { continue }
    if ($addr -eq '::1' -or $addr -eq '127.0.0.1') { continue }
    if ([string]$ip.AddressState -eq 'Tentative' -or [string]$ip.AddressState -eq 'Duplicate') { continue }
    $addresses += [pscustomobject]@{
      address      = $addr
      family       = [string]$ip.AddressFamily
      interface    = [string]$ip.InterfaceAlias
      prefixLength = if ($null -ne $ip.PrefixLength) { [int]$ip.PrefixLength } else { $null }
      prefixOrigin = [string]$ip.PrefixOrigin
    }
  }

  $totalMemoryGb = $null
  if ($cs -and $cs.TotalPhysicalMemory) {
    $totalMemoryGb = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
  }

  $payload = [ordered]@{
    hostname        = [string]$os.CSName
    caption         = [string]$os.Caption
    productName     = if ($cv.ProductName) { [string]$cv.ProductName } else { [string]$os.Caption }
    editionId       = if ($cv.EditionID) { [string]$cv.EditionID } else { $null }
    displayVersion  = if ($cv.DisplayVersion) { [string]$cv.DisplayVersion } else { $null }
    releaseId       = if ($cv.ReleaseId) { [string]$cv.ReleaseId } else { $null }
    version         = [string]$os.Version
    buildNumber     = $buildNumber
    ubr             = $ubr
    build           = $build
    architecture    = [string]$os.OSArchitecture
    language        = [string]$os.OSLanguage
    manufacturer    = if ($cs) { [string]$cs.Manufacturer } else { $null }
    model           = if ($cs) { [string]$cs.Model } else { $null }
    pcSystemType    = if ($cs -and $null -ne $cs.PCSystemType) { [int]$cs.PCSystemType } else { $null }
    chassisTypes    = $chassis
    totalMemoryGb   = $totalMemoryGb
    bootTime        = if ($os.LastBootUpTime) { ([datetime]$os.LastBootUpTime).ToString('o') } else { $null }
    collectedAt     = (Get-Date).ToString('o')
    timeZone        = if ($tz) { [string]$tz.Id } else { $null }
    addresses       = $addresses
  }

  $json = ConvertTo-Json -InputObject $payload -Compress -Depth 6
}
catch {
  $json = ConvertTo-Json -InputObject @{ __collectorError = $_.Exception.Message } -Compress
}

Write-Output ('@@ARES@@' + $json)
