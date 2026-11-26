function Get-EntraPasskeyAccessToken {
    <#
    .SYNOPSIS
    Authenticates with a software or Key Vault passkey and acquires an Entra OAuth2 access token.
    .DESCRIPTION
    Performs experimental Entra passkey authentication via Invoke-EntraPasskeyLogin, then uses
    the resulting authenticated session with OAuth2 Authorization Code + PKCE to acquire a
    delegated access token (and optional refresh token) for the requested client and scopes.
    AccessToken and RefreshToken are returned as SecureString by default; use -AsPlainText,
    -RawToken, or -Json for automation output.
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
    process {
        $clientGuid = [guid]::Empty
        if (-not [guid]::TryParse($ClientId, [ref]$clientGuid) -or $clientGuid -eq [guid]::Empty) {
            throw 'ClientId must be a nonempty application GUID.'
        }
        $normalizedClientId = $clientGuid.ToString()
        $null = Test-EntraPasskeyTenantIdFormat -TenantId $TenantId
        $resolvedScopes = Resolve-EntraPasskeyScopes -Scope $Scope -IncludeRefreshToken:$IncludeRefreshToken

        $login = $null
        $pkce = $null
        $authCode = $null
        $tokenPayload = $null
        try {
            $login = Invoke-EntraPasskeyLoginForSession -BoundParameters $PSBoundParameters -CredentialFromPipeline $CredentialFromPipeline -QuietWarningsToStderr:($RawToken -or $Json)
            $authority = Resolve-EntraPasskeyAuthority -TenantId $TenantId -UserPrincipalName $login.UserPrincipalName -UserAgent $UserAgent -Proxy $Proxy
            $pkce = New-EntraPkceChallenge
            $authCode = Get-EntraAuthorizationCodeFromSession `
                -WebSession $login.AuthenticationSession `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -RedirectUri $RedirectUri `
                -Scopes $resolvedScopes `
                -UserPrincipalName $login.UserPrincipalName `
                -Pkce $pkce `
                -Claims $Claims `
                -UserAgent $UserAgent `
                -Proxy $Proxy

            $tokenPayload = Request-EntraTokenByAuthorizationCode `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -Code $authCode `
                -RedirectUri $RedirectUri `
                -CodeVerifier $pkce.Verifier `
                -Scopes $resolvedScopes `
                -Claims $Claims `
                -SpaOrigin $SpaOrigin `
                -UserAgent $UserAgent `
                -Proxy $Proxy

            Format-EntraPasskeyTokenResult `
                -TokenPayload $tokenPayload `
                -LoginResult $login `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -AuthFlow 'PasskeyAuthorizationCodePKCE' `
                -AsPlainText:$AsPlainText `
                -RawToken:$RawToken `
                -Json:$Json
        } finally {
            $authCode = $null
            if ($pkce) { $pkce.Verifier = $null }
            if ($tokenPayload) {
                $tokenPayload.access_token = $null
                $tokenPayload.refresh_token = $null
            }
            Clear-EntraPasskeyLoginSession -LoginResult $login
        }
    }
}
