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

Describe 'Entra registration module imports' {
    It 'loads both modules from the curated script location' {
        $ast = Read-ScriptAst 'Register-EntraKeyVaultPasskey.ps1'
        $assignment = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$moduleRoot' }
        $imports = $ast.EndBlock.Statements | Where-Object { $_.Extent.Text -like 'Import-Module *' }
        $imports.Count | Should -Be 2
        & {
            # Model the actual script root while evaluating only the import statements.
            $sourceScriptRoot = Join-Path $RepositoryRoot 'powershell/scripts/entra'
            . ([scriptblock]::Create($assignment.Extent.Text.Replace('$PSScriptRoot', '$sourceScriptRoot')))
            foreach ($statement in $imports) { . ([scriptblock]::Create($statement.Extent.Text)) }
            Get-Command ConvertTo-Base64Url -Module Passkey.Common | Should -Not -BeNullOrEmpty
            foreach ($name in @('Passkey.Common', 'Passkey.EntraAuth')) {
                (Get-Module $name).Path | Should -Be (Resolve-Path (Join-Path $RepositoryRoot "powershell/modules/$name/$name.psm1")).Path
            }
        }
    }
}

Describe 'Entra registration Az token compatibility' {
    It 'preserves a complete SecureString token in <Path>' -ForEach @(
        @{ Path = 'Register-EntraKeyVaultPasskey.ps1' }
        @{ Path = 'reference/Register-EntraKeyVaultPasskeyViaTap.ps1' }
        @{ Path = 'reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1' }
    ) {
        $ast = Read-ScriptAst $Path
        $assignment = $ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$kvToken' -and $node.Right.Extent.Text -match '\$azToken.Token'
        }, $true)
        $assignment.Count | Should -Be 1
        $expected = 'offline-token-ABC.123-é-漢字'
        $azToken = [pscustomobject]@{ Token = ConvertTo-SecureString $expected -AsPlainText -Force }
        . ([scriptblock]::Create($assignment[0].Extent.Text))
        $kvToken | Should -BeOfType ([string])
        "Bearer $kvToken" | Should -BeExactly "Bearer $expected"
        # Older Az.Accounts versions returned a string. Retain that contract too.
        $azToken.Token = $expected
        . ([scriptblock]::Create($assignment[0].Extent.Text))
        $kvToken | Should -BeExactly $expected
    }
}

Describe 'Entra reference SecureString compatibility' {
    It 'decodes every secret conversion without raw unmanaged allocations in <Path>' -ForEach @(
        @{ Path = 'reference/Invoke-EntraPasskeyLogin.ps1'; ExpectedCount = 2 }
        @{ Path = 'reference/Register-EntraSoftwarePasskey.ps1'; ExpectedCount = 3 }
    ) {
        $ast = Read-ScriptAst $Path
        $ast.Extent.Text | Should -Not -Match 'PtrToStringAuto|SecureStringToBSTR'
        $expressions = $ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.MemberExpressionAst] -and
            $node.Extent.Text -match '^\[System.Net.NetworkCredential\]::new\(' -and
            $node.Member.Extent.Text -eq 'Password'
        }, $true)
        $expressions.Count | Should -Be $ExpectedCount
        $expected = "offline-secret-é-漢字`nsecond-line"
        $secret = ConvertTo-SecureString $expected -AsPlainText -Force
        $azToken = [pscustomobject]@{ Token = $secret }
        $PrivateKey = $secret
        $ClientSecret = $secret
        $ClientCertificatePassword = $secret
        foreach ($expression in $expressions) {
            & ([scriptblock]::Create($expression.Extent.Text)) | Should -BeExactly $expected
        }
    }
}

Describe 'Research security boundaries remain intact' {
    It 'throws before creating an assertion for either key backend' {
        $ast = Read-ScriptAst 'reference/Invoke-EntraPasskeyLogin.ps1'
        $guard = $ast.Find({ param($node)
            $node -is [System.Management.Automation.Language.ThrowStatementAst] -and
            $node.Extent.Text -match 'Software-backed assertions are disabled'
        }, $true)
        $guard | Should -Not -BeNullOrEmpty
        $guard.Parent.Statements[0] | Should -Be $guard
        { & ([scriptblock]::Create($guard.Extent.Text)) } | Should -Throw -ExceptionType ([System.NotSupportedException])
    }

    It 'retains none attestation and no synthetic packed attestation in <Path>' -ForEach @(
        @{ Path = 'Register-EntraKeyVaultPasskey.ps1' }
        @{ Path = 'reference/Register-EntraKeyVaultPasskeyViaTap.ps1' }
        @{ Path = 'reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1' }
        @{ Path = 'reference/Register-EntraSoftwarePasskey.ps1' }
    ) {
        $ast = Read-ScriptAst $Path
        $ast.Extent.Text | Should -Match 'fmt["'']?\s*=\s*["'']none["'']'
        $ast.Extent.Text | Should -Not -Match 'fmt["'']?\s*=\s*["'']packed["'']'
    }
}
