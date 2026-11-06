Describe 'Isolated Function PowerShell LTS runtime' {
    BeforeAll {
        $repoRoot = Join-Path $PSScriptRoot '../..'
        $bicep = Get-Content (Join-Path $repoRoot 'function-app/powershell/keyvault-passkey-http/infra/main.bicep') -Raw
    }

    It 'selects only PowerShell 7.6 on the existing Flex Consumption plan' {
        $bicep | Should -Match "@allowed\(\[\s*'7\.6'\s*\]\)\s*param functionAppRuntimeVersion string = '7\.6'"
        $bicep | Should -Match "sku:\s*\{(?=[^}]*name: 'FC1')(?=[^}]*tier: 'FlexConsumption')"
        $bicep | Should -Match 'runtime:\s*\{\s*name: functionAppRuntime\s*version: functionAppRuntimeVersion'
        $bicep | Should -Not -Match "'7\.4'|'Y1'"
    }

    It 'keeps sensitive runtime validation and deployment behind separate authorization' {
        $readme = Get-Content (Join-Path $repoRoot 'function-app/powershell/keyvault-passkey-http/README.md') -Raw
        $readme | Should -Match 'PowerShell 7\.6 / \.NET 10 LTS'
        $readme | Should -Match 'Do not run live login, credential'
        $readme | Should -Match 'private\s+endpoint/code-push preflight'
        $automation = Get-Content (Join-Path $repoRoot 'azure-automation/function-passkey-runbooks/README.md') -Raw
        $automation | Should -Match '\*\*PowerShell 7\.6\*\* runbook runtime'
    }
}
