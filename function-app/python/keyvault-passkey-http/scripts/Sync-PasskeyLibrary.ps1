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

$repoRootFull = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
$sampleRootFull = [System.IO.Path]::GetFullPath($sampleRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
$sourceRootFull = [System.IO.Path]::GetFullPath($sourceRoot)
$destinationRootFull = [System.IO.Path]::GetFullPath($destinationRoot)
if (-not $sourceRootFull.StartsWith("$repoRootFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Canonical library resolved outside the repository: $sourceRootFull"
}
if (-not $destinationRootFull.StartsWith("$sampleRootFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Library destination resolved outside the Function sample: $destinationRootFull"
}

New-Item -ItemType Directory -Force -Path $destinationRoot | Out-Null
Get-ChildItem -LiteralPath $destinationRoot -Force | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force
}
Get-ChildItem -LiteralPath $sourceRoot -Force | Where-Object {
    $_.Name -ne '__pycache__' -and $_.Extension -ne '.pyc'
} | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $destinationRoot -Recurse -Force
}

Write-Host "Python Function sample library assets refreshed from $sourceRoot" -ForegroundColor Green
