param($QueueItem, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

$configuration = Get-OktaFunctionConfiguration
$payload = if ($QueueItem -is [string]) { $QueueItem | ConvertFrom-Json -AsHashtable -Depth 20 } else { $QueueItem | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable }
$requestId = [string]$payload.requestId
if ([string]::IsNullOrWhiteSpace($requestId)) { throw 'Okta queue message is missing requestId.' }

Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
    requestId = $requestId
    provider = 'okta'
    authMethod = 'idx'
    status = 'processing'
    queueName = (Get-OktaRegistrationQueueName)
    oktaDomain = [string]$payload.oktaDomain
    warning = 'Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.'
})

try {
    $userName = [string]($payload.userName ?? 'okta')
    $outputPath = New-TempOutputPath -UserPrincipalName $userName -AuthMethod 'okta-idx'
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Register-OktaKeyVaultPasskeyViaIdxSession.ps1'
    $parameters = @{
        OktaDomain = [string]$payload.oktaDomain
        CookieHeader = [string]$payload.cookieHeader
        StateHandle = [string]$payload.stateHandle
        AuthenticatorId = [string]$payload.authenticatorId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
        OutputPath = $outputPath
        Transport = [string]($payload.transport ?? 'usb')
    }
    if ($payload.keyVaultKeyName) { $parameters.KeyVaultKeyName = [string]$payload.keyVaultKeyName }
    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $parameters
    Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
        requestId = $requestId
        provider = 'okta'
        authMethod = 'idx'
        status = 'succeeded'
        queueName = (Get-OktaRegistrationQueueName)
        oktaDomain = [string]$payload.oktaDomain
        completedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        credential = $credential
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
