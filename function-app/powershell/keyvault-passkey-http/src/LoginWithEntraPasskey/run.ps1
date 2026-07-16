using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')
    $userAgent = Resolve-RequestUserAgent -Body $body -Request $Request
    $credential = Get-CredentialPayload -Body $body

    if ($credential.Count -eq 0) {
        throw [System.ArgumentException]::new("Request body must include a credential object or passkey login credential fields.")
    }

    if (-not $credential.ContainsKey('credentialId')) {
        throw [System.ArgumentException]::new("Credential is missing required field 'credentialId'.")
    }

    if (-not $credential.ContainsKey('userHandle')) {
        throw [System.ArgumentException]::new("Credential is missing required field 'userHandle'.")
    }

    $configuration = Get-PasskeyFunctionConfiguration
    if (-not [string]::IsNullOrWhiteSpace($configuration.KeyVaultName) -or -not [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
        if (-not $credential.ContainsKey('keyVault') -or $credential.keyVault -isnot [System.Collections.IDictionary]) {
            $credential.keyVault = @{}
        }
        $credential.keyVault.vaultName = $configuration.KeyVaultName
        if (-not [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
            $credential.keyVault.keyName = $keyVaultKeyName
        }
    }

    $keyVaultAccessToken = Get-KeyVaultAccessToken -Configuration $configuration
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1'

    $loginParameters = @{
        KeyVaultAccessToken = $keyVaultAccessToken
        KeyVaultTenantId    = $configuration.TenantId
    }
    $authUrl = [Environment]::GetEnvironmentVariable('PASSKEY_ENTRA_AUTH_URL')
    if (-not [string]::IsNullOrWhiteSpace($authUrl)) {
        $loginParameters.AuthUrl = $authUrl
    }
    if (-not [string]::IsNullOrWhiteSpace($userAgent)) {
        $loginParameters.UserAgent = $userAgent
    }

    $login = Invoke-PasskeyLoginScript -ScriptPath $scriptPath -Credential $credential -Parameters $loginParameters
    $result = $login.Result
    $statusCode = if ($result.Success) { [HttpStatusCode]::OK } else { [HttpStatusCode]::Unauthorized }

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode $statusCode -NoStore -Body ([ordered]@{
        success = [bool]$result.Success
        authMethod = 'passkey'
        userPrincipalName = $result.UserPrincipalName
        signatureMethod = $result.SignatureMethod
        keyVaultName = $result.KeyVaultName
        cookieType = $result.CookieType
        estsAuth = $login.ESTSAuthCookie
        estsAuthCookie = $login.ESTSAuthCookie
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -NoStore -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::InternalServerError) -NoStore -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
}
