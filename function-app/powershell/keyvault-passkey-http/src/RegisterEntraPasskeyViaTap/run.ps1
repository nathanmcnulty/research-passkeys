using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $userPrincipalName = Get-RequestValue -Body $body -Request $Request -Names @('userPrincipalName', 'username', 'email')
    $tap = Get-RequestValue -Body $body -Request $Request -Names @('tap', 'temporaryAccessPass')
    $displayName = Get-RequestValue -Body $body -Request $Request -Names @('displayName')
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')
    $userAgent = Resolve-RequestUserAgent -Body $body -Request $Request
    $redirectUri = Resolve-RequestRedirectUri -Body $body -Request $Request

    if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
        throw [System.ArgumentException]::new("Missing required field 'userPrincipalName', 'username', or 'email'.")
    }

    if ([string]::IsNullOrWhiteSpace($tap)) {
        throw [System.ArgumentException]::new("Missing required field 'tap' or 'temporaryAccessPass'.")
    }

    $configuration = Get-PasskeyFunctionConfiguration
    $keyVaultAccessToken = Get-KeyVaultAccessToken -Configuration $configuration
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\entra\Register-EntraKeyVaultPasskey.ps1'
    $outputPath = New-TempOutputPath -UserPrincipalName $userPrincipalName -AuthMethod 'tap'

    $scriptParameters = @{
        TAP = $tap
        UserPrincipalName = $userPrincipalName
        TenantId = $configuration.TenantId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = $keyVaultAccessToken
        OutputPath = $outputPath
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        $scriptParameters.DisplayName = $displayName
    }

    if (-not [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
        $scriptParameters.KeyVaultKeyName = $keyVaultKeyName
    }

    if (-not [string]::IsNullOrWhiteSpace($userAgent)) {
        $scriptParameters.UserAgent = $userAgent
    }

    if (-not [string]::IsNullOrWhiteSpace($redirectUri)) {
        $scriptParameters.RedirectUri = $redirectUri
    }

    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $scriptParameters
    $extensions = Save-PasskeyLoginAndCaptureContext -Provider entra -Body $body -Credential $credential -Configuration $configuration -UserAgent $userAgent
    $catalogRecord = Save-PasskeyCatalogRecord -Provider entra -Credential $credential -Configuration $configuration -Extensions $extensions

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        authMethod = 'tap'
        tenantId = $configuration.TenantId
        keyVaultName = $configuration.KeyVaultName
        credential = $credential
        catalogRecord = $catalogRecord
        loginPropagation = Get-PostRegistrationLoginHint
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
}
