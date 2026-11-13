# Ares - network endpoint collector (read-only)
# Emits listening TCP sockets and bound UDP endpoints with owning process where available.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-ProcessNameMap {
  $map = @{}
  foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
    try { $map[[int]$p.Id] = [string]$p.ProcessName } catch { }
  }
  return $map
}

function Get-ServiceMap {
  $map = @{}
  foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
    try {
      $pidValue = [int]$s.ProcessId
      if ($pidValue -gt 0) { $map[$pidValue] = [string]$s.Name }
    } catch { }
  }
  return $map
}

try {
  $tcp = @()
  $udp = @()
  $source = 'Get-NetTCPConnection'

  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
      [pscustomobject]@{
        protocol = 'tcp'
        address  = [string]$_.LocalAddress
        port     = [int]$_.LocalPort
        state    = [string]$_.State
        pid      = [int]$_.OwningProcess
      }
    })
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
      $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
          protocol = 'udp'
          address  = [string]$_.LocalAddress
          port     = [int]$_.LocalPort
          state    = 'bound'
          pid      = [int]$_.OwningProcess
        }
      })
    }
  }

  if ($tcp.Count -eq 0) {
    $source = 'netstat'
    $netstat = @(netstat -ano -p tcp 2>$null)
    foreach ($line in $netstat) {
      $parts = ($line -replace '\s+', ' ').Trim().Split(' ')
      if ($parts.Count -lt 4) { continue }
      if ($parts[0] -ne 'TCP') { continue }
      if ($parts[3] -ne 'LISTENING') { continue }
      $local = $parts[1]
      $idx = $local.LastIndexOf(':')
      if ($idx -lt 1) { continue }
      $addr = $local.Substring(0, $idx).Trim('[', ']')
      $portValue = 0
      if (-not [int]::TryParse($local.Substring($idx + 1), [ref]$portValue)) { continue }
      $pidValue = 0
      if (-not [int]::TryParse($parts[4], [ref]$pidValue)) { $pidValue = 0 }
      $tcp += [pscustomobject]@{ protocol = 'tcp'; address = $addr; port = $portValue; state = 'Listen'; pid = $pidValue }
    }
    $netstatUdp = @(netstat -ano -p udp 2>$null)
    foreach ($line in $netstatUdp) {
      $parts = ($line -replace '\s+', ' ').Trim().Split(' ')
      if ($parts.Count -lt 4) { continue }
      if ($parts[0] -ne 'UDP') { continue }
      $local = $parts[1]
      $idx = $local.LastIndexOf(':')
      if ($idx -lt 1) { continue }
      $addr = $local.Substring(0, $idx).Trim('[', ']')
      $portValue = 0
      if (-not [int]::TryParse($local.Substring($idx + 1), [ref]$portValue)) { continue }
      $pidValue = 0
      if (-not [int]::TryParse($parts[3], [ref]$pidValue)) { $pidValue = 0 }
      $udp += [pscustomobject]@{ protocol = 'udp'; address = $addr; port = $portValue; state = 'bound'; pid = $pidValue }
    }
  }

  $processNames = Get-ProcessNameMap
  $serviceNames = Get-ServiceMap

  $endpoints = @()
  foreach ($item in ($tcp + $udp)) {
    $processName = $null
    $serviceName = $null
    try {
      if ($item.pid -gt 0) {
        if ($processNames.ContainsKey($item.pid)) { $processName = $processNames[$item.pid] }
        if ($serviceNames.ContainsKey($item.pid)) { $serviceName = $serviceNames[$item.pid] }
      }
    } catch { }
    $endpoints += [pscustomobject]@{
      protocol    = $item.protocol
      address     = $item.address
      port        = $item.port
      state       = $item.state
      pid         = $item.pid
      process     = $processName
      service     = $serviceName
      loopbackOnly = ($item.address -eq '127.0.0.1' -or $item.address -eq '::1')
      anyAddress  = ($item.address -eq '0.0.0.0' -or $item.address -eq '::' -or $item.address -eq '[::]')
    }
  }

  $payload = [ordered]@{
    source      = $source
    collectedAt = (Get-Date).ToString('o')
    endpoints   = $endpoints
    counts      = [ordered]@{ tcp = $tcp.Count; udp = $udp.Count }
    processLookupAvailable = ($processNames.Count -gt 0)
  }

  $json = ConvertTo-Json -InputObject $payload -Compress -Depth 6
}
catch {
  $json = ConvertTo-Json -InputObject @{ __collectorError = $_.Exception.Message } -Compress
}

Write-Output ('@@ARES@@' + $json)
