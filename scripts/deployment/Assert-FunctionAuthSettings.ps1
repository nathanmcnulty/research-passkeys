function Assert-FunctionAuthSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$AuthSettings,
        [Parameter(Mandatory)][string]$ExpectedIssuer,
        [Parameter(Mandatory)][string]$BrowserExtensionClientId
    )

    $settings = $AuthSettings.properties
    if ($null -eq $settings -or $settings.platform.enabled -ne $true -or
        $settings.globalValidation.requireAuthentication -ne $true -or
        $settings.globalValidation.unauthenticatedClientAction -ne 'Return401' -or
        $settings.httpSettings.requireHttps -ne $true) {
        throw 'Effective Function authentication does not require HTTPS and global Easy Auth with Return401.'
    }

    $aad = $settings.identityProviders.azureActiveDirectory
    if ($null -eq $aad -or $aad.enabled -ne $true -or
        $aad.registration.clientId -ne $BrowserExtensionClientId -or
        $aad.registration.openIdIssuer -ne $ExpectedIssuer) {
        throw 'Effective Function authentication has an unexpected Entra issuer or client application.'
    }

    $providers = $settings.identityProviders | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
    foreach ($providerName in $providers.Keys) {
        if ($providerName -eq 'azureActiveDirectory') { continue }
        $provider = $providers[$providerName]
        if ($providerName -eq 'customOpenIdConnectProviders') {
            foreach ($customProvider in @($provider.Values)) {
                if ($customProvider.enabled -eq $true) {
                    throw 'Effective Function authentication enables another identity provider.'
                }
            }
        } elseif ($provider.enabled -eq $true) {
            throw 'Effective Function authentication enables another identity provider.'
        }
    }

    $expectedAudience = "api://$BrowserExtensionClientId"
    $audiences = @($aad.validation.allowedAudiences)
    $applications = @($aad.validation.defaultAuthorizationPolicy.allowedApplications)
    if ($audiences.Count -ne 1 -or $audiences[0] -ne $expectedAudience -or
        $applications.Count -ne 1 -or $applications[0] -ne $BrowserExtensionClientId) {
        throw 'Effective Function authentication has an unexpected audience or allowed calling application.'
    }

    if (@($settings.globalValidation.excludedPaths).Where({ -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0) {
        throw 'Effective Function authentication excludes routes from Easy Auth; this source contract requires none.'
    }
}
