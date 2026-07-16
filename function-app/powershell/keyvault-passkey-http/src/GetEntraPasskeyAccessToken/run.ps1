using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $configuration = Get-PasskeyBrokerConfiguration
    $tokenRequest = Resolve-PasskeyBrokerTokenRequest -Body $body -Configuration $configuration
    $recordId = [string]$Request.Params.recordId
    $record = Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if (-not $record -or [string]$record.provider -ne 'entra') {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -NoStore -Body @{ success = $false; error = 'Entra passkey was not found.' })
        return
    }

    $context = Get-PasskeyLoginContext -Configuration $configuration -Record $record
    $record.keyVault.vaultName = $configuration.KeyVaultName
    try {
        $login = Invoke-PasskeyLoginScript -ScriptPath (Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1') `
            -Credential $record -Parameters @{
                KeyVaultAccessToken = (Get-KeyVaultAccessToken -Configuration $configuration)
                KeyVaultTenantId = $configuration.TenantId
                UserAgent = (Normalize-PasskeyUserAgent $context.userAgent)
            }
    } catch {
        Write-Warning 'Stored passkey authentication failed.'
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Unauthorized -NoStore -Body @{ success = $false; error = 'Passkey authentication failed.' })
        return
    }
    if (-not $login.Result.Success -or -not $login.WebSession) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Unauthorized -NoStore -Body @{ success = $false; error = 'Passkey authentication failed.' })
        return
    }

    $token = Request-PasskeyBrokerAccessToken -Configuration $configuration -TokenRequest $tokenRequest `
        -UserPrincipalName ([string]$login.Result.UserPrincipalName) -WebSession $login.WebSession
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body ([ordered]@{
        success = $true
        tokenType = $token.TokenType
        accessToken = $token.AccessToken
        expiresOn = $token.ExpiresOn
        tenantId = $token.TenantId
        accountId = $token.AccountId
        profile = $token.Profile
        scopes = @($token.Scopes)
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode BadRequest -NoStore -Body @{ success = $false; error = $_.Exception.Message })
} catch {
    Write-Warning 'Passkey token acquisition failed during the upstream authentication exchange.'
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode BadGateway -NoStore -Body @{ success = $false; error = 'Passkey token acquisition failed.' })
}
