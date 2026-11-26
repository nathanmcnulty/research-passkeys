#Requires -Version 7.6

<#
.SYNOPSIS
Runs or completes an Entra device code flow using a software or Key Vault passkey to get an access token.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Requests an Entra device code (or accepts an external -UserCode), authenticates with
the passkey credential, approves the device login prompt, and polls for the access token.
Returns SecureString token values by default; use -AsPlainText, -RawToken, or -Json
for automation pipelines.
.EXAMPLE
./Get-EntraPasskeyAccessTokenViaDeviceCode.ps1 -KeyFilePath ./passkey.json -RawToken
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
    [string]$Claims,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRefreshToken,

    [Parameter(Mandatory = $false)]
    [string]$UserCode,

    [Parameter(Mandatory = $false)]
    [string]$VerificationUri = 'https://login.microsoftonline.com/common/oauth2/deviceauth',

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds,

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
Get-EntraPasskeyAccessTokenViaDeviceCode @PSBoundParameters
