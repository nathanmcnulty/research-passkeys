#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Creates the smallest practical Entra app registration for GitHub Actions OIDC.

.DESCRIPTION
    This helper creates or reuses:
    - an application registration
    - its service principal
    - one GitHub Actions federated credential for a branch
    - an optional Key Vault Crypto User role assignment on a named Key Vault

    It is intentionally minimal for this repository. It does not assign API permissions,
    or create client secrets. After running it, use the emitted client ID and tenant ID
    with azure/login.

.PARAMETER AppName
    Display name for the Entra application registration.

.PARAMETER GitHubRepo
    GitHub repository in owner/repo format.

.PARAMETER Branch
    Branch name allowed to request tokens through the federated credential.

.PARAMETER KeyVaultName
    Optional Key Vault name. When provided, the script resolves the vault and grants
    the service principal the Key Vault Crypto User role on that vault.

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/action-passkey-login' -Branch 'main'

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1 -KeyVaultName 'kv-passkeys-prod'
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName = 'action-passkey-login',

    [Parameter()]
    [string]$GitHubRepo = 'nathanmcnulty/action-passkey-login',

    [Parameter()]
    [string]$Branch = 'main',

    [Parameter()]
    [string]$KeyVaultName
)

$ErrorActionPreference = 'Stop'

function Normalize-OptionalString {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $trimmedValue = $Value.Trim()
    if ($trimmedValue.Length -eq 0) {
        return $null
    }

    return $trimmedValue
}

function Invoke-AzCliJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$AllowFailure
    )

    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFailure) {
            return $null
        }

        throw "Azure CLI command failed: az $($Arguments -join ' ')`n$output"
    }

    if (-not $output) {
        return $null
    }

    return $output | ConvertFrom-Json
}

function Test-AzLoggedIn {
    & az account show --output none 2>$null
    return $LASTEXITCODE -eq 0
}

function Get-FirstOrNull {
    param(
        [AllowNull()]
        [object[]]$InputObject
    )

    return @($InputObject) | Select-Object -First 1
}

function Get-OrCreateApplication {
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    Write-Host "Checking application '$DisplayName'..." -ForegroundColor Cyan
    $appList = Invoke-AzCliJson -Arguments @('ad', 'app', 'list', '--display-name', $DisplayName, '--output', 'json')
    $app = Get-FirstOrNull (@($appList | Where-Object { $_.displayName -eq $DisplayName }))

    if ($app) {
        Write-Host 'Reusing existing application registration.' -ForegroundColor Yellow
        return $app
    }

    $app = Invoke-AzCliJson -Arguments @('ad', 'app', 'create', '--display-name', $DisplayName, '--sign-in-audience', 'AzureADMyOrg', '--output', 'json')
    Write-Host 'Created application registration.' -ForegroundColor Green
    return $app
}

function Get-OrCreateServicePrincipal {
    param(
        [Parameter(Mandatory)]
        [string]$AppId
    )

    $servicePrincipal = Invoke-AzCliJson -Arguments @('ad', 'sp', 'show', '--id', $AppId, '--output', 'json') -AllowFailure
    if ($servicePrincipal) {
        Write-Host 'Reusing existing service principal.' -ForegroundColor Yellow
        return $servicePrincipal
    }

    $servicePrincipal = Invoke-AzCliJson -Arguments @('ad', 'sp', 'create', '--id', $AppId, '--output', 'json')
    Write-Host 'Created service principal.' -ForegroundColor Green
    return $servicePrincipal
}

function Get-OrCreateFederatedCredential {
    param(
        [Parameter(Mandatory)]
        [string]$ApplicationObjectId,
        [Parameter(Mandatory)]
        [string]$CredentialName,
        [Parameter(Mandatory)]
        [string]$Subject
    )

    $existingCredentials = Invoke-AzCliJson -Arguments @('ad', 'app', 'federated-credential', 'list', '--id', $ApplicationObjectId, '--output', 'json')
    $namedCredential = Get-FirstOrNull (@($existingCredentials | Where-Object { $_.name -eq $CredentialName }))

    if ($namedCredential -and $namedCredential.subject -ne $Subject) {
        Invoke-AzCliJson -Arguments @(
            'ad', 'app', 'federated-credential', 'delete',
            '--id', $ApplicationObjectId,
            '--federated-credential-id', $namedCredential.id,
            '--output', 'json'
        ) -AllowFailure | Out-Null

        Write-Host 'Removed federated credential with mismatched subject.' -ForegroundColor Yellow
        $namedCredential = $null
    }

    $matchingCredential = $namedCredential
    if (-not $matchingCredential) {
        $matchingCredential = Get-FirstOrNull (@($existingCredentials | Where-Object { $_.subject -eq $Subject }))
    }

    if ($matchingCredential) {
        Write-Host 'Reusing existing federated credential.' -ForegroundColor Yellow
        return $matchingCredential
    }

    $credentialDefinition = @{
        name = $CredentialName
        issuer = 'https://token.actions.githubusercontent.com'
        subject = $Subject
        audiences = @('api://AzureADTokenExchange')
    } | ConvertTo-Json -Depth 5

    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("federated-credential-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    try {
        Set-Content -Path $tempFile -Value $credentialDefinition -NoNewline
        $matchingCredential = Invoke-AzCliJson -Arguments @('ad', 'app', 'federated-credential', 'create', '--id', $ApplicationObjectId, '--parameters', $tempFile, '--output', 'json')
        Write-Host 'Created federated credential.' -ForegroundColor Green
        return $matchingCredential
    } finally {
        Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
    }
}

function Get-KeyVaultWithCryptoUserAssignment {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$ServicePrincipalObjectId
    )

    Write-Host "Checking Key Vault '$Name'..." -ForegroundColor Cyan
    $vault = Invoke-AzCliJson -Arguments @('keyvault', 'show', '--name', $Name, '--output', 'json') -AllowFailure

    if (-not $vault) {
        throw "Key Vault '$Name' was not found in the current Azure context."
    }

    $existingAssignment = Invoke-AzCliJson -Arguments @(
        'role', 'assignment', 'list',
        '--assignee-object-id', $ServicePrincipalObjectId,
        '--scope', $vault.id,
        '--role', 'Key Vault Crypto User',
        '--output', 'json'
    )

    if (-not $existingAssignment -or @($existingAssignment).Count -eq 0) {
        Invoke-AzCliJson -Arguments @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $ServicePrincipalObjectId,
            '--assignee-principal-type', 'ServicePrincipal',
            '--role', 'Key Vault Crypto User',
            '--scope', $vault.id,
            '--output', 'json'
        ) | Out-Null

        Write-Host "Granted 'Key Vault Crypto User' on '$($vault.name)'." -ForegroundColor Green
    } else {
        Write-Host "Reusing existing 'Key Vault Crypto User' assignment on '$($vault.name)'." -ForegroundColor Yellow
    }

    return $vault
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required. Install Azure CLI and run az login first.'
}

if (-not (Test-AzLoggedIn)) {
    throw 'No Azure CLI session found. Run az login first.'
}

$AppName = Normalize-OptionalString $AppName
$GitHubRepo = Normalize-OptionalString $GitHubRepo
$Branch = Normalize-OptionalString $Branch
$KeyVaultName = Normalize-OptionalString $KeyVaultName

if (-not $AppName) {
    throw 'AppName cannot be empty.'
}
if (-not $GitHubRepo -or $GitHubRepo -notmatch '^[^/]+/[^/]+$') {
    throw 'GitHubRepo must be in owner/repo format.'
}
if (-not $Branch) {
    throw 'Branch cannot be empty.'
}

$account = Invoke-AzCliJson -Arguments @('account', 'show', '--output', 'json')
$tenantId = $account.tenantId

Write-Host "Connected tenant: $tenantId" -ForegroundColor Cyan
$app = Get-OrCreateApplication -DisplayName $AppName
$sp = Get-OrCreateServicePrincipal -AppId $app.appId

$credentialName = "github-$($Branch.Replace('/', '-'))"
$subject = "repo:${GitHubRepo}:ref:refs/heads/${Branch}"
$null = Get-OrCreateFederatedCredential -ApplicationObjectId $app.id -CredentialName $credentialName -Subject $subject

$keyVault = $null
if ($KeyVaultName) {
    $keyVault = Get-KeyVaultWithCryptoUserAssignment -Name $KeyVaultName -ServicePrincipalObjectId $sp.id
}

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host ""
Write-Host "GitHub repository: https://github.com/$GitHubRepo" -ForegroundColor Cyan
Write-Host "Application (client) ID: $($app.appId)" -ForegroundColor Yellow
Write-Host "Tenant ID: $tenantId" -ForegroundColor Yellow
Write-Host "Service principal object ID: $($sp.id)" -ForegroundColor Yellow
Write-Host "Federated subject: $subject" -ForegroundColor Yellow
Write-Host ""
Write-Host "Recommended GitHub settings:" -ForegroundColor Cyan
Write-Host "  AZURE_CLIENT_ID  = $($app.appId)" -ForegroundColor White
Write-Host "  AZURE_TENANT_ID  = $tenantId" -ForegroundColor White
Write-Host ""
if ($keyVault) {
    Write-Host "Key Vault role assignment:" -ForegroundColor Cyan
    Write-Host "  Vault name: $($keyVault.name)" -ForegroundColor White
    Write-Host "  Role: Key Vault Crypto User" -ForegroundColor White
} else {
    Write-Host "Next step for Key Vault-backed signing:" -ForegroundColor Cyan
    Write-Host "  Re-run with -KeyVaultName <vault-name> or grant this service principal 'Key Vault Crypto User' on the target Key Vault or key scope." -ForegroundColor White
}