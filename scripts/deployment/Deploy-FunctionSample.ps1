[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')]
    [string]$TemplateId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$SubscriptionId = 'a80941e8-c2b9-4bc9-83ad-117cc40d0bea',

    [Parameter()]
    [string]$Location = 'westus2',

    [Parameter()]
    [string]$TenantId = '847b5907-ca15-40f4-b171-eb18619dbfab',

    [Parameter()]
    [string]$EnvironmentName = 'sample',

    [Parameter()]
    [string]$AzConfigDir,

    [Parameter()]
    [switch]$SkipWhatIf,

    [Parameter()]
    [switch]$SkipCodeDeploy,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI was not found. Install Azure CLI before using this deployment helper.'
}

if ([string]::IsNullOrWhiteSpace($AzConfigDir)) {
    $tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $AzConfigDir = Join-Path $tempRoot 'azcfg-research-passkeys'
}
New-Item -ItemType Directory -Path $AzConfigDir -Force | Out-Null
$env:AZURE_CONFIG_DIR = $AzConfigDir

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sampleMap = @{
    'powershell-keyvault-passkey-http' = @{
        SampleRoot  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http'
        SyncScript  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http\scripts\Sync-PasskeyAssets.ps1'
        SourceRoot  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http\src'
        BuildRemote = $false
    }
    'python-keyvault-passkey-http' = @{
        SampleRoot  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http'
        SyncScript  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http\scripts\Sync-PasskeyLibrary.ps1'
        SourceRoot  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http\src'
        BuildRemote = $true
    }
}

$sample = $sampleMap[$TemplateId]
$sampleRoot = [string]$sample.SampleRoot
$syncScript = [string]$sample.SyncScript
$sourceRoot = [string]$sample.SourceRoot
$infraPath = Join-Path $sampleRoot 'infra\main.bicep'

if (-not (Test-Path -LiteralPath $sampleRoot)) {
    throw "Sample root not found: $sampleRoot"
}
if (-not (Test-Path -LiteralPath $infraPath)) {
    throw "Bicep template not found: $infraPath"
}
if (-not (Test-Path -LiteralPath $sourceRoot)) {
    throw "Function source root not found: $sourceRoot"
}

if (Test-Path -LiteralPath $syncScript) {
    & $syncScript
}

& az account set --subscription $SubscriptionId | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to select subscription $SubscriptionId."
}

& az group create --name $ResourceGroupName --location $Location --output none | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create or select resource group $ResourceGroupName."
}

$parameterArgs = @(
    '--parameters', "location=$Location",
    '--parameters', "tenantId=$TenantId",
    '--parameters', "environmentName=$EnvironmentName"
)

if (-not $SkipWhatIf) {
    & az deployment group what-if `
        --resource-group $ResourceGroupName `
        --template-file $infraPath `
        @parameterArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'Bicep what-if failed.'
    }
}

$deploymentJson = & az deployment group create `
    --resource-group $ResourceGroupName `
    --template-file $infraPath `
    @parameterArgs `
    --query properties.outputs `
    --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Bicep deployment failed.'
}

$deploymentOutputs = $deploymentJson | ConvertFrom-Json
$functionAppName = [string]$deploymentOutputs.functionAppName.value
$functionAppDefaultHostname = [string]$deploymentOutputs.functionAppDefaultHostname.value
$keyVaultName = [string]$deploymentOutputs.keyVaultName.value
$managedIdentityClientId = [string]$deploymentOutputs.managedIdentityClientId.value

$tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
$zipPath = Join-Path $tempRoot "$TemplateId-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
try {
    if (-not $SkipCodeDeploy) {
        Compress-Archive -Path (Join-Path $sourceRoot '*') -DestinationPath $zipPath -Force

        $deployArgs = @(
            'functionapp', 'deployment', 'source', 'config-zip',
            '--src', $zipPath,
            '--name', $functionAppName,
            '--resource-group', $ResourceGroupName
        )
        if ([bool]$sample.BuildRemote) {
            $deployArgs += @('--build-remote', 'true')
        }

        & az @deployArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Function code deployment failed for $functionAppName."
        }
    }
} finally {
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

$result = [PSCustomObject]@{
    templateId                = $TemplateId
    resourceGroupName         = $ResourceGroupName
    subscriptionId            = $SubscriptionId
    location                  = $Location
    environmentName           = $EnvironmentName
    azConfigDir               = $AzConfigDir
    functionAppName           = $functionAppName
    functionAppDefaultHostname = $functionAppDefaultHostname
    keyVaultName              = $keyVaultName
    managedIdentityClientId   = $managedIdentityClientId
    codeDeployed              = -not $SkipCodeDeploy
}

if ($PassThru) {
    Write-Output $result
} else {
    $result | ConvertTo-Json -Compress
}
