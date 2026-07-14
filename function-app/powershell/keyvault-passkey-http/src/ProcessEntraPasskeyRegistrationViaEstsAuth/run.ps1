param($QueueItem, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

$message = $QueueItem
if ($QueueItem -is [byte[]]) {
    $message = [System.Text.Encoding]::UTF8.GetString($QueueItem)
}

if ($message -is [string]) {
    $message = $message | ConvertFrom-Json -AsHashtable -Depth 20
} elseif ($message -isnot [System.Collections.IDictionary]) {
    $message = ($message | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable)
}

$userPrincipalName = [string]($message.userPrincipalName ?? '')
$configuration = Get-PasskeyFunctionConfiguration
if ($message.captureContext -isnot [System.Collections.IDictionary]) { throw "Queue message is missing encrypted capture context." }
$capturedBody = Export-PasskeyCapturePayload -Configuration $configuration -Context $message.captureContext
$estsAuthCookie = [string]($capturedBody.estsAuth ?? $capturedBody.estsAuthCookie ?? '')
$displayName = [string]($message.displayName ?? $message.passkeyDisplayName ?? '')
$keyVaultKeyName = [string]($message.keyVaultKeyName ?? '')
$requestId = [string]($message.requestId ?? '')
$userAgent = Normalize-PasskeyUserAgent -UserAgent ($message.userAgent ?? $message.useragent)
$redirectUri = Normalize-PasskeyRedirectUri -RedirectUri ([Environment]::GetEnvironmentVariable('PASSKEY_ENTRA_PORTAL_ORIGIN'))

if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
    throw "Queue message is missing 'userPrincipalName'."
}

if ([string]::IsNullOrWhiteSpace($estsAuthCookie)) {
    throw "Queue message is missing 'estsAuth'."
}

$processingStartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
Set-RegistrationStatus -RequestId $requestId -Status ([ordered]@{
    requestId = $requestId
    status = 'processing'
    authMethod = 'estsauth'
    queueName = Get-RegistrationQueueName
    userPrincipalName = $userPrincipalName
    displayName = $displayName
    keyVaultKeyName = $keyVaultKeyName
    queuedAtUtc = [string]($message.queuedAtUtc ?? '')
    processingStartedAtUtc = $processingStartedAtUtc
    userAgent = $userAgent
    redirectUri = $redirectUri
})

try {
    $registration = Invoke-EstsAuthPasskeyRegistration `
        -UserPrincipalName $userPrincipalName `
        -EstsAuthCookie $estsAuthCookie `
        -DisplayName $displayName `
        -KeyVaultKeyName $keyVaultKeyName `
        -UserAgent $userAgent `
        -RedirectUri $redirectUri

    $credential = $registration.Credential
    $extensions = Save-PasskeyLoginAndCaptureContext -Provider entra -Body $capturedBody -Credential $credential -Configuration $registration.Configuration -UserAgent $userAgent
    $catalogRecord = Save-PasskeyCatalogRecord -Provider entra -Credential $credential -Configuration $registration.Configuration -Extensions $extensions
    $keyName = $null
    if ($credential.keyVault -is [System.Collections.IDictionary]) {
        $keyName = [string]$credential.keyVault.keyName
    }

    Set-RegistrationStatus -RequestId $requestId -Status ([ordered]@{
        requestId = $requestId
        status = 'succeeded'
        authMethod = 'estsauth'
        queueName = Get-RegistrationQueueName
        userPrincipalName = $userPrincipalName
        displayName = $displayName
        keyVaultKeyName = $keyVaultKeyName
        keyVaultName = [string]($registration.Configuration.KeyVaultName ?? '')
        queuedAtUtc = [string]($message.queuedAtUtc ?? '')
        processingStartedAtUtc = $processingStartedAtUtc
        completedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        userAgent = $userAgent
        redirectUri = $redirectUri
        credential = $credential
        catalogRecord = $catalogRecord
    })

    Write-Host "Processed ESTSAUTH passkey registration request $requestId for $userPrincipalName with key $keyName."
} catch {
    Set-RegistrationStatus -RequestId $requestId -Status ([ordered]@{
        requestId = $requestId
        status = 'failed'
        authMethod = 'estsauth'
        queueName = Get-RegistrationQueueName
        userPrincipalName = $userPrincipalName
        displayName = $displayName
        keyVaultKeyName = $keyVaultKeyName
        queuedAtUtc = [string]($message.queuedAtUtc ?? '')
        failedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        userAgent = $userAgent
        redirectUri = $redirectUri
        error = $_.Exception.Message
    })
    throw
}
