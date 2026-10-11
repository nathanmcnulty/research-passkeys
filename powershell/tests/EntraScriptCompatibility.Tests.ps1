param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

# Offline only: execute individual syntax-tree expressions, never an enrollment or login script.
BeforeAll {
    function Read-ScriptAst([string]$RelativePath) {
        $tokens = $null
        $errors = $null
        $path = Join-Path $RepositoryRoot "powershell/scripts/entra/$RelativePath"
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw "Parse errors in $RelativePath" }
        return $ast
    }
}

Describe 'Shared legacy modules remain usable by unrelated callers' {
    It 'imports existing modules without authentication and preserves the shared browser-header function identity' {
        Mock Invoke-WebRequest {throw 'Unexpected network'}
        Mock Invoke-RestMethod {throw 'Unexpected network'}
        foreach ($name in @('Passkey.Common','Passkey.EntraAuth')) {
            Import-Module (Join-Path $RepositoryRoot "powershell/modules/$name/$name.psm1") -Force
            (Get-Module $name).Path | Should -Be (Resolve-Path (Join-Path $RepositoryRoot "powershell/modules/$name/$name.psm1")).Path
        }
        Get-Command ConvertTo-Base64Url -Module Passkey.Common | Should -Not -BeNullOrEmpty
        $original=(Get-Command Add-PasskeyBrowserHeaders -Module Passkey.EntraAuth).Definition.Trim()
        $tokens=$null;$errors=$null
        $sourceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'powershell/src/Entra/SoftwareBrowserHeaders.ps1'),[ref]$tokens,[ref]$errors)
        $declaration=$sourceAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-PasskeyBrowserHeaders'},$false)
        $declaration.Body.Extent.Text.TrimStart('{').TrimEnd('}').Trim() | Should -BeExactly $original
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
    }
}
Describe 'Canonical SecureString compatibility' {
    BeforeAll { . (Join-Path $RepositoryRoot 'powershell/src/Common/Values.ps1') }
    It 'preserves complete string and SecureString values without caller state changes' {
        $expected="offline-secret-é-漢字`nsecond-line"
        ConvertTo-PlainTextValue (ConvertTo-SecureString $expected -AsPlainText -Force) | Should -BeExactly $expected
        ConvertTo-PlainTextValue $expected | Should -BeExactly $expected
        ConvertTo-PlainTextValue $null | Should -BeNullOrEmpty
    }
    It 'keeps generated Key Vault token conversion compatible across string and SecureString Az versions' {
        . (Join-Path $RepositoryRoot 'powershell/src/KeyVault/Token.ps1')
        function Get-AzAccessToken {param($ResourceUrl,$TenantId)}
        $expected='offline-token-ABC.123-é-漢字'
        Mock Get-AzAccessToken { @{Token=(ConvertTo-SecureString 'offline-token-ABC.123-é-漢字' -AsPlainText -Force)} }
        Get-KeyVaultToken | Should -BeExactly $expected
        Mock Get-AzAccessToken { @{Token='offline-token-ABC.123-é-漢字'} }
        Get-KeyVaultToken | Should -BeExactly $expected
    }

}
Describe 'Explicit research software assertion contract' {
    It 'restores local and Key Vault login through separate reviewed signers without claiming trusted UP/UV' {
        $ast=Read-ScriptAst 'reference/Invoke-EntraPasskeyLogin.ps1'
        $ast.Extent.Text | Should -Not -Match 'Software-backed assertions are disabled'
        $ast.Extent.Text | Should -Match 'Invoke-LocalPasskeySignHash|Invoke-KeyVaultPasskeySignHash'
        $ast.Extent.Text | Should -Match 'UserPresenceVerified=\$false'
        $ast.Extent.Text | Should -Match 'UserVerificationVerified=\$false'
    }
    It 'retains none attestation in the generated canonical registration commands' -ForEach @(
        @{Path='Register-EntraKeyVaultPasskey.ps1'},
        @{Path='reference/Register-EntraKeyVaultPasskeyViaTap.ps1'},
        @{Path='reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1'},
        @{Path='reference/Register-EntraSoftwarePasskey.ps1'}
    ) {
        $ast=Read-ScriptAst $Path
        if ($Path -eq 'reference/Register-EntraSoftwarePasskey.ps1') {
            $flow=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-EntraSoftwareGraphRegistration'},$false)
            $flow.Extent.Text | Should -Match 'New-EntraSoftwareAttestation.*-Format None'
        } else {
            $ast.Extent.Text | Should -Match 'fmt["'']?\s*=\s*["'']none["'']'
            $ast.Extent.Text | Should -Not -Match 'fmt["'']?\s*=\s*["'']packed["'']'
        }
    }
}
