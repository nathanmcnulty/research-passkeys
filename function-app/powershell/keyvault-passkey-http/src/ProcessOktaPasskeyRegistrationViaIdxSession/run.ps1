param($QueueItem, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

$configuration = Get-OktaFunctionConfiguration
$oktaDomain = Resolve-OktaDomain -Body @{} -Request ([pscustomobject]@{ Query = @{} })
$payload = if ($QueueItem -is [string]) { $QueueItem | ConvertFrom-Json -AsHashtable -Depth 20 } else { $QueueItem | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable }
$requestId = [string]$payload.requestId
if ([string]::IsNullOrWhiteSpace($requestId)) { throw 'Okta queue message is missing requestId.' }
if ($payload.captureContext -isnot [System.Collections.IDictionary]) { throw 'Okta queue message is missing encrypted capture context.' }
$capturedBody = Export-PasskeyCapturePayload -Configuration $configuration -Context $payload.captureContext

Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
    requestId = $requestId
    provider = 'okta'
    authMethod = 'idx'
    status = 'processing'
    queueName = (Get-OktaRegistrationQueueName)
    oktaDomain = $oktaDomain
    warning = 'Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.'
})

try {
    $userName = [string]($payload.userName ?? 'okta')
    $outputPath = New-TempOutputPath -UserPrincipalName $userName -AuthMethod 'okta-idx'
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Register-OktaKeyVaultPasskeyViaIdxSession.ps1'
    $parameters = @{
        OktaDomain = $oktaDomain
        CookieHeader = [string]($capturedBody.cookieHeader ?? $capturedBody.cookie)
        StateHandle = [string]$capturedBody.stateHandle
        AuthenticatorId = [string]$capturedBody.authenticatorId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
        OutputPath = $outputPath
        Transport = [string]($payload.transport ?? 'usb')
    }
    if ($payload.keyVaultKeyName) { $parameters.KeyVaultKeyName = [string]$payload.keyVaultKeyName }
    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $parameters
    $extensions = Save-PasskeyLoginAndCaptureContext -Provider okta -Body $capturedBody -Credential $credential -Configuration $configuration -UserAgent ([string]($capturedBody.user_agent ?? $capturedBody.userAgent))
    $catalogRecord = Save-PasskeyCatalogRecord -Provider okta -Credential $credential -Configuration $configuration -Extensions $extensions
    Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
        requestId = $requestId
        provider = 'okta'
        authMethod = 'idx'
        status = 'succeeded'
        queueName = (Get-OktaRegistrationQueueName)
        oktaDomain = $oktaDomain
        completedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        credential = $credential
        catalogRecord = $catalogRecord
    })
} catch {
    Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
        requestId = $requestId
        provider = 'okta'
        authMethod = 'idx'
        status = 'failed'
        queueName = (Get-OktaRegistrationQueueName)
        oktaDomain = [string]$payload.oktaDomain
        failedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        error = $_.Exception.Message
    })
    throw
}
