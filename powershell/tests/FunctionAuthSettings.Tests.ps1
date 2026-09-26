BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\scripts\deployment\Assert-FunctionAuthSettings.ps1')
    $issuer = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0'
    $client = '22222222-2222-2222-2222-222222222222'
}

Describe 'Effective Function authentication gate' {
BeforeEach {
    $auth = @{
        properties = @{
            platform = @{ enabled = $true }
            globalValidation = @{ requireAuthentication = $true; unauthenticatedClientAction = 'Return401'; excludedPaths = @() }
            httpSettings = @{ requireHttps = $true }
            identityProviders = @{
                azureActiveDirectory = @{
                    enabled = $true
                    registration = @{ clientId = $client; openIdIssuer = $issuer }
                    validation = @{
                        allowedAudiences = @("api://$client")
                        defaultAuthorizationPolicy = @{ allowedApplications = @($client) }
                    }
                }
            }
        }
    }
}

    It 'accepts the exact source contract' {
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Not -Throw
    }

    It 'rejects a disabled Easy Auth platform' {
        $auth.properties.platform.enabled = $false
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
    }

    It 'rejects anonymous access and HTTP' {
        $auth.properties.globalValidation.requireAuthentication = $false
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
        $auth.properties.globalValidation.requireAuthentication = $true
        $auth.properties.httpSettings.requireHttps = $false
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
    }

    It 'rejects a wrong issuer, audience or calling application' {
        $aad = $auth.properties.identityProviders.azureActiveDirectory
        $aad.registration.openIdIssuer = 'https://wrong.example/v2.0'
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
        $aad.registration.openIdIssuer = $issuer
        $aad.validation.allowedAudiences = @('api://wrong')
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
        $aad.validation.allowedAudiences = @("api://$client")
        $aad.validation.defaultAuthorizationPolicy.allowedApplications = @('wrong')
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
    }

    It 'rejects Queue route exclusions' {
        $auth.properties.globalValidation.excludedPaths = @('/api/entra/passkeys/*/queue')
        { Assert-FunctionAuthSettings -AuthSettings $auth -ExpectedIssuer $issuer -BrowserExtensionClientId $client } | Should -Throw
    }
}
