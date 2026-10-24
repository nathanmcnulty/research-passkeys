#!/usr/bin/env pwsh
#Requires -Version 7.6
<#
.SYNOPSIS
    Creates the smallest practical Entra app registration for GitHub Actions OIDC.

.DESCRIPTION
    This helper creates or reuses:
    - an application registration
    - its service principal
    - one GitHub Actions federated credential for a verified repository subject
    - an optional Key Vault Crypto User role assignment on a named Key Vault

    It is intentionally minimal for this repository. It does not assign API permissions,
    or create client secrets. After running it, use the emitted client ID and tenant ID
    with azure/login.

.PARAMETER AppName
    Display name for the Entra application registration.

.PARAMETER GitHubRepo
    Required consuming GitHub repository in owner/repo format. There is no default.
    Omission fails without prompting and before any Azure CLI command.

.PARAMETER Branch
    Branch name for a job without an environment (defaults to main).
    Mutually exclusive with Environment and OidcSubject.

.PARAMETER Environment
    GitHub environment used by the workflow job, such as entra-prod.

.PARAMETER OidcSubject
    Exact subject verified against the consuming job's OIDC configuration. Must start
    with this repository's repo segment, optionally with immutable owner/repository IDs.
    The script does not discover or verify GitHub's live configuration.

.PARAMETER GitHubOwnerId
    Verified numeric owner ID, paired with GitHubRepositoryId, for immutable subjects.
    Without these IDs, Branch and Environment construct the legacy name-only format.

.PARAMETER GitHubRepositoryId
    Verified numeric repository ID, paired with GitHubOwnerId, for immutable subjects.

.PARAMETER KeyVaultName
    Optional Key Vault name. When provided, the script resolves the vault and grants
    the service principal the Key Vault Crypto User role on that vault.

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/automation' -Environment 'entra-prod'

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/action-passkey-login' -Branch 'main'

.EXAMPLE
    .\scripts\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/automation' -Environment 'entra-prod' -KeyVaultName 'kv-passkeys-prod'
#>

[CmdletBinding(DefaultParameterSetName = 'Branch')]
param(
    [Parameter()]
    [string]$AppName = 'action-passkey-login',

    [Parameter()]
    [string]$GitHubRepo,

    [Parameter(ParameterSetName = 'Branch')]
    [string]$Branch = 'main',

    [Parameter(Mandatory, ParameterSetName = 'Environment')]
    [ValidateNotNullOrEmpty()]
    [string]$Environment,

    [Parameter(Mandatory, ParameterSetName = 'Subject')]
    [ValidateNotNullOrEmpty()]
    [string]$OidcSubject,

    [Parameter(ParameterSetName = 'Branch')]
    [Parameter(ParameterSetName = 'Environment')]
    [ValidatePattern('^[1-9][0-9]*$')]
    [string]$GitHubOwnerId,

    [Parameter(ParameterSetName = 'Branch')]
    [Parameter(ParameterSetName = 'Environment')]
    [ValidatePattern('^[1-9][0-9]*$')]
    [string]$GitHubRepositoryId,

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
    $matchingApps = @($appList | Where-Object { $_.displayName -eq $DisplayName })
    if ($matchingApps.Count -gt 1) {
        throw 'Multiple application registrations match AppName. Choose a unique application display name before continuing; no application was selected.'
    }
    $app = Get-FirstOrNull $matchingApps

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

    # Trust properties are case-sensitive. Never replace an existing credential, and
    # never reuse one just because its name or subject happens to match.
    $candidates = @($existingCredentials | Where-Object {
        $_.name -eq $CredentialName -or $_.subject -ceq $Subject
    })
    foreach ($candidate in $candidates) {
        if ($candidate.subject -cne $Subject -or
            $candidate.issuer -cne 'https://token.actions.githubusercontent.com' -or
            @($candidate.audiences).Count -ne 1 -or
            $candidate.audiences[0] -cne 'api://AzureADTokenExchange') {
            throw "Existing federated credential '$($candidate.name)' has incompatible subject, issuer, or audiences. No credential was changed. Review it manually; this helper never replaces trust."
        }
    }

    $matchingCredential = Get-FirstOrNull $candidates
    if ($matchingCredential) {
        Write-Host 'Reusing existing federated credential with identical trust.' -ForegroundColor Yellow
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

# Validate the complete trust request before checking Azure CLI or reading its session.
# Do not mark GitHubRepo Mandatory: omission must throw instead of prompting in automation.
if (-not $PSBoundParameters.ContainsKey('GitHubRepo') -or [string]::IsNullOrWhiteSpace($GitHubRepo)) {
    throw 'GitHubRepo is required. Supply the consuming repository explicitly in owner/repo format.'
}
if ($GitHubRepo -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9_.-]+$' -or
    ($GitHubRepo.Split('/')[1] -in @('.', '..'))) {
    throw 'GitHubRepo must be in owner/repo format, without URLs, whitespace, or IDs.'
}
$AppName = Normalize-OptionalString $AppName
$KeyVaultName = Normalize-OptionalString $KeyVaultName
if (-not $AppName) {
    throw 'AppName cannot be empty.'
}
if ([bool]$GitHubOwnerId -ne [bool]$GitHubRepositoryId) {
    throw 'GitHubOwnerId and GitHubRepositoryId must be supplied together for immutable subjects.'
}

$owner, $repository = $GitHubRepo.Split('/')
$repositorySubject = $GitHubRepo
if ($GitHubOwnerId) {
    $repositorySubject = "${owner}@${GitHubOwnerId}/${repository}@${GitHubRepositoryId}"
}

switch ($PSCmdlet.ParameterSetName) {
    'Subject' {
        # A supplied subject is not normalized: Entra and GitHub must agree exactly.
        $ownerPattern = [regex]::Escape($owner)
        $repositoryPattern = [regex]::Escape($repository)
        $repositoryPrefix = "^repo:(?:${ownerPattern}/${repositoryPattern}|${ownerPattern}@[1-9][0-9]*/${repositoryPattern}@[1-9][0-9]*):.+$"
        if ($OidcSubject -cnotmatch $repositoryPrefix) {
            throw 'OidcSubject must start with the exact GitHubRepo repo segment, with either both immutable IDs or neither, followed by the verified job context.'
        }
        $subject = $OidcSubject
    }
    'Environment' {
        if ([string]::IsNullOrWhiteSpace($Environment) -or $Environment -cne $Environment.Trim()) {
            throw 'Environment cannot be empty or have leading/trailing whitespace.'
        }
        # GitHub percent-encodes colons inside metadata values, not other characters.
        $subject = "repo:${repositorySubject}:environment:$($Environment.Replace(':', '%3A'))"
    }
    default {
        if ([string]::IsNullOrWhiteSpace($Branch) -or $Branch -cne $Branch.Trim()) {
            throw 'Branch cannot be empty or have leading/trailing whitespace.'
        }
        $subject = "repo:${repositorySubject}:ref:refs/heads/$($Branch.Replace(':', '%3A'))"
    }
}
if ($subject.Length -gt 600 -or $subject -match '[\x00-\x1F\x7F*]' -or $subject -cne $subject.Trim()) {
    throw 'The OIDC subject must be at most 600 characters with no control characters, wildcards, or leading/trailing whitespace.'
}

# The complete trust tuple, including its case, gives a stable, URL-safe 71-character
# name that avoids truncation, repository-reuse, and slash-replacement collisions.
$trustBytes = [Text.Encoding]::UTF8.GetBytes("https://token.actions.githubusercontent.com`n${subject}`napi://AzureADTokenExchange")
$credentialName = 'github-' + [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($trustBytes)).ToLowerInvariant()

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required. Install Azure CLI and run az login first.'
}
if (-not (Test-AzLoggedIn)) {
    throw 'No Azure CLI session found. Run az login first.'
}

$account = Invoke-AzCliJson -Arguments @('account', 'show', '--output', 'json')
$tenantId = $account.tenantId

Write-Host "Connected tenant: $tenantId" -ForegroundColor Cyan
$app = Get-OrCreateApplication -DisplayName $AppName
$sp = Get-OrCreateServicePrincipal -AppId $app.appId

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
    Write-Host "  Re-run with the same repository and subject arguments plus -KeyVaultName <vault-name>, or grant this service principal 'Key Vault Crypto User' on the target Key Vault or key scope." -ForegroundColor White
}
