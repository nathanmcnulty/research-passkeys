using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $configuration = Get-PasskeyBrokerConfiguration
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body ([ordered]@{
        success = $true
        tenantId = $configuration.TenantId
        tokenClientId = $configuration.TokenClientId
        tokenRedirectUri = $configuration.TokenRedirectUri
        profiles = @(
            [ordered]@{ name = 'MicrosoftGraph'; defaultScopes = @('User.Read'); allowedScopes = @($configuration.GraphAllowedScopes) }
            [ordered]@{ name = 'AzureResourceManager'; defaultScopes = @('https://management.azure.com/user_impersonation'); allowedScopes = @('https://management.azure.com/user_impersonation') }
        )
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode BadRequest -NoStore -Body @{ success = $false; error = $_.Exception.Message })
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -NoStore -Body @{ success = $false; error = 'Broker configuration is unavailable.' })
}
