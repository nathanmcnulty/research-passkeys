#Requires -Version 7.6

<#
.SYNOPSIS
Experimental Entra login using a local software key or a Key Vault signing key.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Unattended software implementation, not a FIDO-certified authenticator. UP/UV flags are synthetic; no authenticator user presence, verification or hardware assurance is provided.
Entra policy can reject this unsupported software flow. OAuth consent is never automated.
Named CredentialId/CredentialIdentifier and UserName/UserPrincipalName are supported.
Use -PassThru for result metadata; -IncludeAuthenticationCookie to return the bearer cookie.
-PersistSessionToGlobalScope explicitly saves ESTSCookie, ESTSCookieName, ESTSAUTH and webSession.
KeyFilePath supports local PEM or a keyVault reference; registered KV versions are preserved.
.EXAMPLE
./Invoke-EntraPasskeyLogin.ps1 -KeyFilePath ./passkey.json -PassThru
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,

    [Parameter(Mandatory = $false)]
    [string]$KeyFilePath,

    [Alias('UserName')]
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$UserHandle,

    [Parameter(Mandatory = $false)]
    [Alias('CredentialId')]
    $CredentialIdentifier,

    [Parameter(Mandatory = $false)]
    $PrivateKey,

    [Parameter(Mandatory = $false)]
    $RelyingParty = "login.microsoft.com",

    [Parameter(Mandatory = $false)]
    $AuthUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

    [switch]$ConfirmApplication,
    [guid]$ExpectedClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [Parameter(Mandatory = $false)]
    $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

    [Parameter(Mandatory = $false)]
    [string]$Proxy,

    # Key Vault parameters (can be provided for manual mode or to override JSON values)
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
    [switch]$PassThru,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuthenticationCookie,

    [Parameter(Mandatory = $false)]
    [switch]$PersistSessionToGlobalScope
)

# Invoke public command
if ($PersistSessionToGlobalScope) {
    # Explicit persistence replaces this authentication state; failed attempts must not leave an old identity.
    foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH','webSession')) {
        Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
    }
}
$arguments=@{}+$PSBoundParameters
$null=$arguments.Remove('PersistSessionToGlobalScope')
$arguments.PassThru=$true
if ($PersistSessionToGlobalScope) {
    $arguments.IncludeAuthenticationCookie=$true
    $arguments.IncludeAuthenticationSession=$true
}
$result=Invoke-EntraPasskeyLogin @arguments
if ($PersistSessionToGlobalScope) {
    if ($result.Success) {
        $global:ESTSCookie=$result.AuthenticationCookieValue
        $global:ESTSCookieName=$result.AuthenticationCookieName
        $global:ESTSAUTH=$result.AuthenticationCookieValue
        $result.TokenVariable='ESTSCookie'
    }
    $global:webSession=$result.AuthenticationSession
    $result.SessionVariable='webSession'
    $result.SessionPersistedToGlobalScope=$true
}
if (-not $IncludeAuthenticationCookie) { $result.AuthenticationCookieValue=$null }
$result.PSObject.Properties.Remove('AuthenticationSession')
if ($PassThru) { $result }
elseif ($result.Success) { Write-Host 'Entra authenticated session verified.' }
else { Write-Warning 'Entra authentication could not be verified.' }
