using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $configuration = Get-OktaFunctionConfiguration
    $credential = Get-CredentialPayload -Body $body
    $userName = Get-RequestValue -Body $body -Request $Request -Names @('userName', 'username', 'email')
    if ([string]::IsNullOrWhiteSpace($userName)) { $userName = [string]($credential.userName ?? $credential.username) }
    if ([string]::IsNullOrWhiteSpace($userName)) { throw [System.ArgumentException]::new("Request must include 'userName' or a credential userName.") }

    $keyVault = if ($credential.keyVault -is [System.Collections.IDictionary]) { [hashtable]$credential.keyVault } else { @{} }
    $keyVaultName = [string]$configuration.KeyVaultName
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')
    if (-not $keyVaultKeyName) { $keyVaultKeyName = [string]$keyVault.keyName }
    $credentialId = [string]$credential.credentialId
    if ([string]::IsNullOrWhiteSpace($credentialId) -or [string]::IsNullOrWhiteSpace($keyVaultName) -or [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
        throw [System.ArgumentException]::new("Credential must include credentialId and Key Vault vaultName/keyName.")
    }

    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Invoke-OktaPasskeyLogin.ps1'
    $parameters = @{
        OktaDomain = (Resolve-OktaDomain -Body $body -Request $Request)
        UserName = $userName
        CredentialId = $credentialId
        KeyVaultName = $keyVaultName
        KeyVaultKeyName = $keyVaultKeyName
        KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
    }
    if ($credential.relyingParty) { $parameters.RelyingParty = [string]$credential.relyingParty }
    $password = Get-RequestValue -Body $body -Request $Request -Names @('password')
    if ($password) { $parameters.Password = ConvertTo-SecureString -String $password -AsPlainText -Force }
    $clientId = Get-RequestValue -Body $body -Request $Request -Names @('clientId')
    if ($clientId) { $parameters.ClientId = $clientId }
    $redirectUri = [Environment]::GetEnvironmentVariable('PASSKEY_OKTA_REDIRECT_URI')
    if ($redirectUri) { $parameters.RedirectUri = $redirectUri }
    $signCount = Get-RequestValue -Body $body -Request $Request -Names @('signCount')
    if ($signCount) { $parameters.SignCount = [uint32]$signCount }

    $result = & $scriptPath @parameters | Select-Object -Last 1
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{ success = $true; provider = 'okta'; authMethod = 'idx'; result = $result }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
}
