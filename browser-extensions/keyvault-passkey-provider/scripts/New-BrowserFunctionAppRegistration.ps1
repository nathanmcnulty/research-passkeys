[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DisplayName = 'Research Passkeys Browser Extension',
    [string]$ExtensionManifestPath = (Join-Path $PSScriptRoot '..\public\manifest.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\.local\browser-function-app-registration.json'),
    [switch]$UseDeviceAuthentication
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw "Invoke-MgGraphRequest is unavailable. Install or import Microsoft.Graph.Authentication before running this script."
}

$manifest = Get-Content -LiteralPath (Resolve-Path -LiteralPath $ExtensionManifestPath) -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace([string]$manifest.key)) {
    throw "The extension manifest must contain a stable 'key'."
}
$hash = [System.Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String([string]$manifest.key))
$extensionId = [System.Text.StringBuilder]::new(32)
foreach ($byte in $hash[0..15]) {
    [void]$extensionId.Append([char](97 + (($byte -shr 4) -band 0x0f)))
    [void]$extensionId.Append([char](97 + ($byte -band 0x0f)))
}
$browserRedirectUri = "https://$($extensionId.ToString()).chromiumapp.org/aad"

$connectParameters = @{ Scopes = @('Application.ReadWrite.All'); NoWelcome = $true }
if ($UseDeviceAuthentication) { $connectParameters.UseDeviceAuthentication = $true }
Connect-MgGraph @connectParameters | Out-Null
try {
    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create single-tenant browser/API application registration')) { return }

    $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' `
        -ContentType 'application/json' -Body (@{
            displayName = $DisplayName
            signInAudience = 'AzureADMyOrg'
            isFallbackPublicClient = $true
        } | ConvertTo-Json -Depth 5 -Compress)
    $scopeId = [guid]::NewGuid()
    $apiScope = [ordered]@{
        id = $scopeId
        adminConsentDescription = 'Allow the browser extension to list passkeys and request constrained assertions.'
        adminConsentDisplayName = 'Access the passkey Function API'
        isEnabled = $true
        type = 'User'
        userConsentDescription = 'Allow this extension to list passkeys and request constrained assertions.'
        userConsentDisplayName = 'Access your passkey Function API'
        value = 'access_as_user'
    }
    $requiredAccess = @(@{
        resourceAppId = $app.appId
        resourceAccess = @(@{ id = $scopeId; type = 'Scope' })
    })
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
        -ContentType 'application/json' -Body (@{
            identifierUris = @("api://$($app.appId)")
            api = @{ oauth2PermissionScopes = @($apiScope) }
            spa = @{ redirectUris = @($browserRedirectUri) }
            requiredResourceAccess = $requiredAccess
        } | ConvertTo-Json -Depth 10 -Compress) | Out-Null
    $servicePrincipal = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        -ContentType 'application/json' -Body (@{ appId = $app.appId } | ConvertTo-Json -Compress)
    $tenantId = [string](Get-MgContext).TenantId
    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        throw 'The Microsoft Graph authentication context did not include a tenant ID.'
    }

    $result = [ordered]@{
        tenantId = $tenantId
        clientId = $app.appId
        applicationObjectId = $app.id
        servicePrincipalObjectId = $servicePrincipal.id
        extensionId = [string]$extensionId
        browserRedirectUri = $browserRedirectUri
        apiAudience = "api://$($app.appId)"
        delegatedScope = "api://$($app.appId)/access_as_user"
        publishedExtensionRequired = $false
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
    $result | ConvertTo-Json -Depth 6
}
finally {
    Disconnect-MgGraph | Out-Null
}
