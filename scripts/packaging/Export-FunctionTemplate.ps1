[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')]
    [string]$TemplateId,

    [Parameter(Mandatory)]
    [string]$DestinationPath
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$templateMap = @{
    'powershell-keyvault-passkey-http' = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http'
    'python-keyvault-passkey-http'     = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http'
}

$sourcePath = $templateMap[$TemplateId]
if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Template source not found: $sourcePath"
}

New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
Copy-Item -Path (Join-Path $sourcePath '*') -Destination $DestinationPath -Recurse -Force

Write-Host "Exported $TemplateId to $DestinationPath" -ForegroundColor Green
