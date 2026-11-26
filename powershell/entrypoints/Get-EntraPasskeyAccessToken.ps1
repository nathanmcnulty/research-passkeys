#Requires -Version 7.6

<#
.SYNOPSIS
Authenticates with a software or Key Vault passkey and returns an Entra OAuth2 access token.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Authenticates using the passkey credential (local private key or Azure Key Vault), then
performs an OAuth2 Authorization Code + PKCE exchange with the authenticated session.
Returns SecureString token values by default; use -AsPlainText, -RawToken, or -Json
for automation pipelines.
.EXAMPLE
./Get-EntraPasskeyAccessToken.ps1 -KeyFilePath ./passkey.json -RawToken
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,

    [Parameter(Mandatory = $false)]
    [string]$KeyFilePath,

    [Alias('UserName')]
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$UserHandle,

    [Alias('CredentialId')]
    [Parameter(Mandatory = $false)]
    $CredentialIdentifier,

    [Parameter(Mandatory = $false)]
    $PrivateKey,

    [Parameter(Mandatory = $false)]
    [string]$RelyingParty = 'login.microsoft.com',

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [Parameter(Mandatory = $false)]
    [string[]]$Scope = @('https://graph.microsoft.com/.default'),

    [Parameter(Mandatory = $false)]
    [string]$RedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient',

    [Parameter(Mandatory = $false)]
    [string]$Claims,

    [Parameter(Mandatory = $false)]
    [string]$SpaOrigin,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRefreshToken,

    [Parameter(Mandatory = $false)]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

    [Parameter(Mandatory = $false)]
    [string]$Proxy,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultKeyName,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultAccessToken,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultClientId,

    [Parameter(Mandatory = $false)]
    [object]$KeyVaultClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultTenantId,

    [Parameter(Mandatory = $false)]
    [switch]$AsPlainText,

    [Parameter(Mandatory = $false)]
    [switch]$RawToken,

    [Parameter(Mandatory = $false)]
    [switch]$Json
)

# Invoke public command
Get-EntraPasskeyAccessToken @PSBoundParameters
