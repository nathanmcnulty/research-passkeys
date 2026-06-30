[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$sampleRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $sampleRoot))
$sourceRoot = Join-Path $repoRoot 'python\libraries\passkey\src\passkey'
$destinationRoot = Join-Path $sampleRoot 'src\passkey'

if (-not (Test-Path -LiteralPath $sourceRoot)) {
    throw "Canonical Python passkey library not found: $sourceRoot"
}

New-Item -ItemType Directory -Force -Path $destinationRoot | Out-Null
Remove-Item -LiteralPath (Join-Path $destinationRoot '*') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $destinationRoot -Recurse -Force

Write-Host "Python Function sample library assets refreshed from $sourceRoot" -ForegroundColor Green
