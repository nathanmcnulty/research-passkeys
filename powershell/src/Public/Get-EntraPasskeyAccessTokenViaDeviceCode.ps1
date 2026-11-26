function Get-EntraPasskeyAccessTokenViaDeviceCode {
    <#
    .SYNOPSIS
    Initiates or completes an Entra device code flow using a software or Key Vault passkey to obtain an access token.
    .DESCRIPTION
    In the default mode (without -UserCode), requests a device code from Entra ID, authenticates
    using Invoke-EntraPasskeyLogin, submits the user code and application confirmation to
    login.microsoftonline.com/common/oauth2/deviceauth, and polls the token endpoint until
    the access token is issued.
    When -UserCode is supplied (for example from an external tool running device code flow),
    authenticates with the passkey and completes the device code prompt for that code without
    polling the token endpoint.
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
    process {
        $externalUserCode = Normalize-OptionalString $UserCode
        if ($externalUserCode -and $RawToken) {
            throw '-RawToken cannot be used with -UserCode because the external caller owns the device_code polling.'
        }
        $clientGuid = [guid]::Empty
        if (-not [guid]::TryParse($ClientId, [ref]$clientGuid) -or $clientGuid -eq [guid]::Empty) {
            throw 'ClientId must be a nonempty application GUID.'
        }
        $normalizedClientId = $clientGuid.ToString()
        $null = Test-EntraPasskeyTenantIdFormat -TenantId $TenantId
        $resolvedScopes = Resolve-EntraPasskeyScopes -Scope $Scope -IncludeRefreshToken:$IncludeRefreshToken

        $login = $null
        $tokenPayload = $null
        try {
            $login = Invoke-EntraPasskeyLoginForSession -BoundParameters $PSBoundParameters -CredentialFromPipeline $CredentialFromPipeline -QuietWarningsToStderr:($RawToken -or $Json)

            if ($externalUserCode) {
                $completion = Complete-EntraDeviceCodeWithSession `
                    -WebSession $login.AuthenticationSession `
                    -UserCode $externalUserCode `
                    -VerificationUri $VerificationUri `
                    -UserAgent $UserAgent `
                    -Proxy $Proxy

                if ($Json) {
                    return ([ordered]@{
                        success                  = $true
                        authFlow                 = 'PasskeyDeviceCodeExternalUserCode'
                        userCode                 = $externalUserCode
                        appName                  = $completion.AppName
                        userPrincipalName        = $login.UserPrincipalName
                        signatureMethod          = $login.SignatureMethod
                        keyVaultName             = $login.KeyVaultName
                        userPresenceVerified     = [bool]$login.UserPresenceVerified
                        userVerificationVerified = [bool]$login.UserVerificationVerified
                    } | ConvertTo-Json -Compress)
                }

                return [pscustomobject]@{
                    Success                  = $true
                    AuthFlow                 = 'PasskeyDeviceCodeExternalUserCode'
                    UserCode                 = $externalUserCode
                    AppName                  = $completion.AppName
                    UserPrincipalName        = $login.UserPrincipalName
                    AuthenticationMethod     = $login.AuthenticationMethod
                    SignatureMethod          = $login.SignatureMethod
                    KeyVaultName             = $login.KeyVaultName
                    UserPresenceVerified     = $login.UserPresenceVerified
                    UserVerificationVerified = $login.UserVerificationVerified
                }
            }

            $authority = Resolve-EntraPasskeyAuthority -TenantId $TenantId -UserPrincipalName $login.UserPrincipalName -UserAgent $UserAgent -Proxy $Proxy
            $deviceCodeResponse = Request-EntraDeviceCode `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -Scopes $resolvedScopes `
                -Claims $Claims `
                -UserAgent $UserAgent `
                -Proxy $Proxy

            $null = Complete-EntraDeviceCodeWithSession `
                -WebSession $login.AuthenticationSession `
                -UserCode ([string]$deviceCodeResponse.user_code) `
                -VerificationUri ([string]$deviceCodeResponse.verification_uri) `
                -UserAgent $UserAgent `
                -Proxy $Proxy

            $interval = if ($null -ne $deviceCodeResponse.interval) { [int]$deviceCodeResponse.interval } else { 5 }
            $expiresIn = if ($PSBoundParameters.ContainsKey('TimeoutSeconds') -and $TimeoutSeconds -gt 0) {
                $TimeoutSeconds
            } elseif ($null -ne $deviceCodeResponse.expires_in) {
                [int]$deviceCodeResponse.expires_in
            } else {
                900
            }

            $tokenPayload = Wait-EntraDeviceCodeToken `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -DeviceCode ([string]$deviceCodeResponse.device_code) `
                -IntervalSeconds $interval `
                -TimeoutSeconds $expiresIn `
                -UserAgent $UserAgent `
                -Proxy $Proxy

            Format-EntraPasskeyTokenResult `
                -TokenPayload $tokenPayload `
                -LoginResult $login `
                -Authority $authority `
                -ClientId $normalizedClientId `
                -AuthFlow 'PasskeyDeviceCode' `
                -UserCode ([string]$deviceCodeResponse.user_code) `
                -AsPlainText:$AsPlainText `
                -RawToken:$RawToken `
                -Json:$Json
        } finally {
            if ($tokenPayload) {
                $tokenPayload.access_token = $null
                $tokenPayload.refresh_token = $null
            }
            Clear-EntraPasskeyLoginSession -LoginResult $login
        }
    }
}
