using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $configuration = Get-OktaFunctionConfiguration
    $cookieHeader = Get-RequestValue -Body $body -Request $Request -Names @('cookieHeader', 'cookie')
    $stateHandle = Get-RequestValue -Body $body -Request $Request -Names @('stateHandle')
    $authenticatorId = Get-RequestValue -Body $body -Request $Request -Names @('authenticatorId')
    if ([string]::IsNullOrWhiteSpace($cookieHeader) -or [string]::IsNullOrWhiteSpace($stateHandle) -or [string]::IsNullOrWhiteSpace($authenticatorId)) {
        throw [System.ArgumentException]::new("Request must include 'cookieHeader', 'stateHandle', and 'authenticatorId'.")
    }
    $transport = Get-RequestValue -Body $body -Request $Request -Names @('transport')
    if ([string]::IsNullOrWhiteSpace($transport)) { $transport = 'usb' }
    if ($transport -notin @('usb', 'internal')) {
        throw [System.ArgumentException]::new("'transport' must be 'usb' or 'internal'.")
    }

    $requestId = [guid]::NewGuid().ToString()
    $queuedAt = (Get-Date).ToUniversalTime().ToString('o')
    $captureContext = Protect-PasskeyQueuedCapture -Configuration $configuration -Provider okta -Body $body -RequestId $requestId
    $queueMessage = [ordered]@{
        requestId = $requestId
        queuedAtUtc = $queuedAt
        provider = 'okta'
        authMethod = 'idx'
        oktaDomain = (Resolve-OktaDomain -Body $body -Request $Request)
        captureContext = $captureContext
        keyVaultKeyName = (Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName'))
        transport = $transport
    }
    Set-RegistrationStatus -RequestId $requestId -Configuration $configuration -Status ([ordered]@{
        requestId = $requestId
        provider = 'okta'
        authMethod = 'idx'
        status = 'queued'
        queueName = (Get-OktaRegistrationQueueName)
        queuedAtUtc = $queuedAt
        oktaDomain = $queueMessage.oktaDomain
        warning = 'Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.'
    })
    Push-OutputBinding -Name RegistrationMessage -Value (($queueMessage | ConvertTo-Json -Depth 20 -Compress))

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::Accepted) -Body ([ordered]@{
        success = $true
        queued = $true
        provider = 'okta'
        authMethod = 'idx'
        requestId = $requestId
        queueName = (Get-OktaRegistrationQueueName)
        statusUrl = (Get-RegistrationStatusUrl -Request $Request -RequestId $requestId -Provider 'okta')
        warning = 'Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.'
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
}
