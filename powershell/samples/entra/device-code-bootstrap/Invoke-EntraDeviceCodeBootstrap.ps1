#Requires -Version 5.1

<#
.SYNOPSIS
    Acquire a delegated Microsoft Graph token by using Azure CLI device code flow.

.DESCRIPTION
    This local bootstrap keeps the delegated-auth path CA-friendly by leaning on Azure CLI's
    `az login --use-device-code` experience instead of ESTS form automation. After sign-in,
    it requests a Microsoft Graph token with `az account get-access-token` and prints a
    compact JSON summary that downstream scripts can consume.

.PARAMETER TenantId
    Tenant to target for login and token acquisition.

.PARAMETER SubscriptionId
    Optional subscription to select after sign-in. This is useful when later steps need Azure
    resource access in the same CLI session.

.PARAMETER Scope
    Optional v2 scopes to request. When omitted, the script uses `--resource-type ms-graph`.

.PARAMETER ResourceType
    Well-known resource type to request when `-Scope` is not provided.

.PARAMETER ForceLogin
    Forces an interactive `az login --use-device-code` before requesting the token.

.PARAMETER PassThru
    Returns the result object instead of compressed JSON.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId = '847b5907-ca15-40f4-b171-eb18619dbfab',

    [Parameter()]
    [string]$SubscriptionId,

    [Parameter()]
    [string[]]$Scope,

    [Parameter()]
    [ValidateSet('aad-graph', 'arm', 'batch', 'data-lake', 'media', 'ms-graph', 'oss-rdbms')]
    [string]$ResourceType = 'ms-graph',

    [Parameter()]
    [switch]$ForceLogin,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Invoke-AzJsonCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI was not found. Install Azure CLI before using this sample."
    }

    $result = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')`n$($result -join [Environment]::NewLine)"
    }

    return $result | ConvertFrom-Json
}

function Invoke-AzInteractiveCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI was not found. Install Azure CLI before using this sample."
    }

    & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }
}

function ConvertFrom-Base64Url {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($base64.Length % 4)) % 4
    if ($padding -gt 0) {
        $base64 += ('=' * $padding)
    }

    return [Convert]::FromBase64String($base64)
}

function Get-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $parts = $AccessToken.Split('.')
    if ($parts.Length -lt 2) {
        throw 'Token did not contain a JWT payload.'
    }

    $payloadBytes = ConvertFrom-Base64Url -Value $parts[1]
    $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
    return $payloadJson | ConvertFrom-Json
}

function Get-ScopeSummary {
    param(
        [Parameter(Mandatory)]
        $Claims
    )

    if ($Claims.PSObject.Properties.Name -contains 'scp' -and $Claims.scp) {
        return [string]$Claims.scp
    }

    if ($Claims.PSObject.Properties.Name -contains 'roles' -and $Claims.roles) {
        if ($Claims.roles -is [System.Array]) {
            return ($Claims.roles -join ' ')
        }

        return [string]$Claims.roles
    }

    return $null
}

function Get-ExpiresInSeconds {
    param(
        [Parameter(Mandatory)]
        $TokenResponse
    )

    if ($TokenResponse.PSObject.Properties.Name -contains 'expires_on' -and $TokenResponse.expires_on) {
        $expiry = [DateTimeOffset]::FromUnixTimeSeconds([int64]$TokenResponse.expires_on)
        return [Math]::Max([int][Math]::Floor(($expiry - [DateTimeOffset]::UtcNow).TotalSeconds), 0)
    }

    return $null
}

function Set-RequestedSubscription {
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        return
    }

    Invoke-AzInteractiveCommand -Arguments @('account', 'set', '--subscription', $SubscriptionId)
}

$tokenArgs = @('account', 'get-access-token', '--output', 'json')
if ($Scope -and $Scope.Count -gt 0) {
    $tokenArgs += @('--scope', ($Scope -join ' '))
} else {
    $tokenArgs += @('--resource-type', $ResourceType)
}
if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
    $tokenArgs += @('--tenant', $TenantId)
}

$tokenResponse = $null
$initialError = $null

if (-not $ForceLogin) {
    try {
        Set-RequestedSubscription
        $tokenResponse = Invoke-AzJsonCommand -Arguments $tokenArgs
    } catch {
        $initialError = $_
    }
}

if (-not $tokenResponse) {
    $loginArgs = @('login', '--use-device-code', '--allow-no-subscriptions')
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $loginArgs += @('--tenant', $TenantId)
    }

    Write-Host 'Starting Azure CLI device code sign-in...' -ForegroundColor Cyan
    Invoke-AzInteractiveCommand -Arguments $loginArgs
    Set-RequestedSubscription
    $tokenResponse = Invoke-AzJsonCommand -Arguments $tokenArgs
}

if (-not $tokenResponse.accessToken) {
    if ($initialError) {
        throw $initialError
    }

    throw 'Azure CLI did not return an access token.'
}

$claims = Get-JwtPayload -AccessToken $tokenResponse.accessToken
$scopeSummary = Get-ScopeSummary -Claims $claims

$result = [PSCustomObject]@{
    success           = $true
    tenantId          = if ($claims.tid) { [string]$claims.tid } else { [string]$tokenResponse.tenant }
    userPrincipalName = if ($claims.preferred_username) { [string]$claims.preferred_username } elseif ($claims.upn) { [string]$claims.upn } else { $null }
    scopes            = $scopeSummary
    expiresIn         = Get-ExpiresInSeconds -TokenResponse $tokenResponse
    subscriptionId    = if ($SubscriptionId) { $SubscriptionId } elseif ($tokenResponse.subscription) { [string]$tokenResponse.subscription } else { $null }
    authSource        = 'azure-cli-device-code'
}

if ($PassThru) {
    Write-Output $result
} else {
    $result | ConvertTo-Json -Compress
}
