[CmdletBinding()]
param(
    [ValidateRange(0, 65535)]
    [int]$Port = 0,
    [switch]$Open
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 20.11 or later is required. Install Node.js and run start again.'
}

$launchArgs = @()
if (-not $Open) { $launchArgs += '--no-open' }
if ($Port -gt 0) { $launchArgs += @('--port', [string]$Port) }
& node (Join-Path $PSScriptRoot 'deploy.mjs') @launchArgs
exit $LASTEXITCODE
