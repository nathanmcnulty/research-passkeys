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

    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = New-DefaultPasskeyDisplayName
    }

    $requestId = [guid]::NewGuid().Guid
    $queueMessage = [ordered]@{
        requestId = $requestId
        queuedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        authMethod = 'estsauth'
        userPrincipalName = $userPrincipalName
        displayName = $displayName
        keyVaultKeyName = $keyVaultKeyName
        estsAuth = $estsAuthCookie
        userAgent = $userAgent
        redirectUri = $redirectUri
    }

    Set-RegistrationStatus -RequestId $requestId -Status ([ordered]@{
        requestId = $requestId
        status = 'queued'
        authMethod = 'estsauth'
        queueName = Get-RegistrationQueueName
        userPrincipalName = $userPrincipalName
        displayName = $displayName
        keyVaultKeyName = $keyVaultKeyName
        queuedAtUtc = $queueMessage.queuedAtUtc
        userAgent = $userAgent
        redirectUri = $redirectUri
    })

    Push-OutputBinding -Name RegistrationMessage -Value ($queueMessage | ConvertTo-Json -Depth 10 -Compress)
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::Accepted) -Body ([ordered]@{
        success = $true
        queued = $true
        authMethod = 'estsauth'
        requestId = $requestId
        queueName = Get-RegistrationQueueName
        userPrincipalName = $userPrincipalName
        statusUrl = Get-RegistrationStatusUrl -Request $Request -RequestId $requestId
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
