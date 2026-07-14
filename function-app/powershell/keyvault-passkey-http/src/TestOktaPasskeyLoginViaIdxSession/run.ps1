using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $configuration = Get-OktaFunctionConfiguration
    $credential = Get-CredentialPayload -Body $body
    $cookieHeader = Get-RequestValue -Body $body -Request $Request -Names @('cookieHeader', 'cookie')
    $stateHandle = Get-RequestValue -Body $body -Request $Request -Names @('stateHandle')
    $challenge = Get-RequestValue -Body $body -Request $Request -Names @('challenge')
    if ([string]::IsNullOrWhiteSpace($cookieHeader) -or [string]::IsNullOrWhiteSpace($stateHandle) -or [string]::IsNullOrWhiteSpace($challenge)) {
        throw [System.ArgumentException]::new("Request must include 'cookieHeader', 'stateHandle', and 'challenge'.")
    }
    $keyVault = if ($credential.keyVault -is [System.Collections.IDictionary]) { [hashtable]$credential.keyVault } else { @{} }
    $keyVaultName = [string]$configuration.KeyVaultName
    $keyVaultKeyName = [string]$keyVault.keyName
    if ([string]::IsNullOrWhiteSpace([string]$credential.credentialId) -or [string]::IsNullOrWhiteSpace($keyVaultName) -or [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
        throw [System.ArgumentException]::new('Credential must include credentialId and Key Vault vaultName/keyName.')
    }

    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Test-OktaPasskeyLoginViaIdxSession.ps1'
    $parameters = @{
        OktaDomain = (Resolve-OktaDomain -Body $body -Request $Request)
        CookieHeader = $cookieHeader
        StateHandle = $stateHandle
        Challenge = $challenge
        CredentialId = [string]$credential.credentialId
        KeyVaultName = $keyVaultName
        KeyVaultKeyName = $keyVaultKeyName
        KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
    }
    $origin = Get-RequestValue -Body $body -Request $Request -Names @('origin', 'url')
    if (-not $origin) { $origin = [string]$credential.url }
    if ($origin) { $parameters.Origin = $origin }
    $signCount = Get-RequestValue -Body $body -Request $Request -Names @('signCount')
    if ($signCount) { $parameters.SignCount = [uint32]$signCount }
    $result = & $scriptPath @parameters | Select-Object -Last 1
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{ success = $true; provider = 'okta'; authMethod = 'idx'; result = $result }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
}
