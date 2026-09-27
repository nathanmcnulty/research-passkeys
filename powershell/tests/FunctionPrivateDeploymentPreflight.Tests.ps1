BeforeAll {
    $deployScript = Join-Path $PSScriptRoot '..\..\scripts\deployment\Deploy-FunctionSample.ps1'
    function az { throw 'Azure CLI must not be called by a rejected code-push request.' }
    $minimumArgs = @{
        TemplateId = 'python-keyvault-passkey-http'
        ResourceGroupName = 'rg-unused-preflight'
        BrowserExtensionClientId = '11111111-1111-4111-8111-111111111111'
    }
}

Describe 'Isolated Function deployment preflight' {
    It 'rejects public-endpoint code push before any Azure command' {
        { & $deployScript @minimumArgs } |
            Should -Throw '*Pass -SkipCodeDeploy*'
    }

    It 'rejects conflicting deployment modes before any Azure command' {
        { & $deployScript @minimumArgs -SkipCodeDeploy -PushCodeThroughPrivateEndpoint } |
            Should -Throw '*Choose either*'
    }
}
