using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $userPrincipalName = Get-RequestValue -Body $body -Request $Request -Names @('userPrincipalName', 'username', 'email')
    $estsAuthCookie = Resolve-EstsAuthCookie -Body $body -Request $Request
    $displayName = Get-RequestValue -Body $body -Request $Request -Names @('displayName', 'passkeyDisplayName')
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')
    $userAgent = Resolve-RequestUserAgent -Body $body -Request $Request
    $redirectUri = Resolve-RequestRedirectUri -Body $body -Request $Request

    if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
        throw [System.ArgumentException]::new("Missing required field 'userPrincipalName', 'username', or 'email'.")
    }

    if ([string]::IsNullOrWhiteSpace($estsAuthCookie)) {
        throw [System.ArgumentException]::new("Missing required field 'estsAuth', 'estsAuthCookie', or a cookie export containing ESTSAUTH.")
    }

    $registration = Invoke-EstsAuthPasskeyRegistration `
        -UserPrincipalName $userPrincipalName `
        -EstsAuthCookie $estsAuthCookie `
        -DisplayName $displayName `
        -KeyVaultKeyName $keyVaultKeyName `
        -UserAgent $userAgent `
        -RedirectUri $redirectUri
    $configuration = $registration.Configuration
    $credential = $registration.Credential
    $extensions = Save-PasskeyLoginAndCaptureContext -Provider entra -Body $body -Credential $credential -Configuration $configuration -UserAgent $userAgent
    $catalogRecord = Save-PasskeyCatalogRecord -Provider entra -Credential $credential -Configuration $configuration -Extensions $extensions

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        authMethod = 'estsauth'
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
    Write-Warning -Message ("RegisterEntraPasskeyViaEstsAuth failed: " + $_.Exception.ToString())
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
}
