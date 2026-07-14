using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $configuration = Get-OktaFunctionConfiguration
    $cookieHeader = Get-RequestValue -Body $body -Request $Request -Names @('cookieHeader', 'cookie')
    $stateHandle = Get-RequestValue -Body $body -Request $Request -Names @('stateHandle')
    $authenticatorId = Get-RequestValue -Body $body -Request $Request -Names @('authenticatorId')
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')
    $transport = Get-RequestValue -Body $body -Request $Request -Names @('transport')
    if ([string]::IsNullOrWhiteSpace($cookieHeader) -or [string]::IsNullOrWhiteSpace($stateHandle) -or [string]::IsNullOrWhiteSpace($authenticatorId)) {
        throw [System.ArgumentException]::new("Request must include 'cookieHeader', 'stateHandle', and 'authenticatorId'.")
    }
    if ([string]::IsNullOrWhiteSpace($transport)) { $transport = 'usb' }
    if ($transport -notin @('usb', 'internal')) {
        throw [System.ArgumentException]::new("'transport' must be 'usb' or 'internal'.")
    }

    $userName = Get-RequestValue -Body $body -Request $Request -Names @('userName', 'username', 'email')
    if ([string]::IsNullOrWhiteSpace($userName)) { $userName = 'okta' }
    $outputPath = New-TempOutputPath -UserPrincipalName $userName -AuthMethod 'okta-idx'
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Register-OktaKeyVaultPasskeyViaIdxSession.ps1'
    $scriptParameters = @{
        OktaDomain = (Resolve-OktaDomain -Body $body -Request $Request)
        CookieHeader = $cookieHeader
        StateHandle = $stateHandle
        AuthenticatorId = $authenticatorId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
        OutputPath = $outputPath
        Transport = $transport
    }
    if ($keyVaultKeyName) { $scriptParameters.KeyVaultKeyName = $keyVaultKeyName }
    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $scriptParameters
    $userAgent = Resolve-RequestUserAgent -Body $body -Request $Request
    $extensions = Save-PasskeyLoginAndCaptureContext -Provider okta -Body $body -Credential $credential -Configuration $configuration -UserAgent $userAgent
    $catalogRecord = Save-PasskeyCatalogRecord -Provider okta -Credential $credential -Configuration $configuration -Extensions $extensions

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        provider = 'okta'
        authMethod = 'idx'
        credential = $credential
        catalogRecord = $catalogRecord
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{
        success = $false
        provider = 'okta'
        error = $_.Exception.Message
    }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{
        success = $false
        provider = 'okta'
        error = $_.Exception.Message
    }))
}
