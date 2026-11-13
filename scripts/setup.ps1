[CmdletBinding()]
param(
    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 20.11 or later is required. Install Node.js and run setup again.'
}

$launchArgs = @()
if (-not $Start) { $launchArgs += '--check' }
& node (Join-Path $PSScriptRoot 'deploy.mjs') @launchArgs
exit $LASTEXITCODE
