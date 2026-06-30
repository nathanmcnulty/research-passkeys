[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$sampleRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $sampleRoot))
$sourceRoot = Join-Path $repoRoot 'powershell'
$assetRoot = Join-Path $sampleRoot 'src\shared\passkey-assets'

New-Item -ItemType Directory -Force -Path (Join-Path $assetRoot 'modules\Passkey.Common') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $assetRoot 'modules\Passkey.EntraAuth') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $assetRoot 'scripts\reference') | Out-Null

Copy-Item (Join-Path $sourceRoot 'modules\Passkey.Common\Passkey.Common.psm1') (Join-Path $assetRoot 'modules\Passkey.Common\Passkey.Common.psm1') -Force
Copy-Item (Join-Path $sourceRoot 'modules\Passkey.EntraAuth\Passkey.EntraAuth.psm1') (Join-Path $assetRoot 'modules\Passkey.EntraAuth\Passkey.EntraAuth.psm1') -Force
Copy-Item (Join-Path $sourceRoot 'scripts\Register-KeyVaultPasskey.ps1') (Join-Path $assetRoot 'scripts\Register-KeyVaultPasskey.ps1') -Force
Copy-Item (Join-Path $sourceRoot 'scripts\reference\Register-KeyVaultPasskeyViaESTSAuth.ps1') (Join-Path $assetRoot 'scripts\reference\Register-KeyVaultPasskeyViaESTSAuth.ps1') -Force

Write-Host "Passkey Function sample assets refreshed from $sourceRoot" -ForegroundColor Green
