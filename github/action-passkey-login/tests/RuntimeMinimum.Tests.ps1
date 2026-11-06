BeforeAll {
    $actionText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '../action.yml')).Replace("`r`n", "`n")
    $match = [regex]::Match($actionText, '(?ms)^    - name: Verify embedded script\n.*?^      run: \|\n(?<body>(?:        [^\n]*\n|\n)+)')
    if (-not $match.Success) { throw 'Missing production Action preflight.' }
    $body = [regex]::Replace($match.Groups['body'].Value, '(?m)^        ', '')
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($body, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Invalid production Action preflight syntax.' }
    $guards = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -match 'PSVersionTable'
    }, $true))
    if ($guards.Count -ne 1) { throw 'Expected exactly one production runtime guard.' }
    # Execute only the actual version guard with a synthetic version value.
    # Never execute the Action, telemetry access, embedded login or network calls.
    $guardBody = $guards[0].Extent.Text.Replace('$PSVersionTable.PSVersion', '$candidate')
    $runtimeGuard = [scriptblock]::Create('param($candidate)' + "`n" + $guardBody)
}

Describe 'Production Action minimum runtime contract' {
    It 'applies the numeric 7.6 minimum to <Version>' -ForEach @(
        @{ Version = '5.1.0'; Accepted = $false },
        @{ Version = '7.0.0'; Accepted = $false },
        @{ Version = '7.5.99'; Accepted = $false },
        @{ Version = '7.6.0'; Accepted = $true },
        @{ Version = '7.6.6'; Accepted = $true },
        @{ Version = '7.6.99'; Accepted = $true },
        @{ Version = '7.7.0'; Accepted = $true },
        @{ Version = '7.10.0'; Accepted = $true },
        @{ Version = '8.0.0'; Accepted = $true }
    ) {
        # Later-version cases establish predicate behavior only, not runtime support testing.
        if ($Accepted) { { & $runtimeGuard ([version]$Version) } | Should -Not -Throw }
        else { { & $runtimeGuard ([version]$Version) } | Should -Throw '*PowerShell 7.6 or later*' }
    }
}

Describe 'Production Action Core runtime value types' {
    It 'applies the floor to SemanticVersion <Version>' -ForEach @(
        @{ Version = '7.5.99'; Accepted = $false },
        @{ Version = '7.6.0'; Accepted = $true },
        @{ Version = '7.6.6'; Accepted = $true },
        @{ Version = '7.7.0'; Accepted = $true },
        @{ Version = '7.10.0'; Accepted = $true },
        @{ Version = '8.0.0'; Accepted = $true }
    ) {
        $value = [System.Management.Automation.SemanticVersion]::Parse($Version)
        $value.GetType().FullName | Should -BeExactly 'System.Management.Automation.SemanticVersion'
        # This tests the real Core value type, not integration on a future runtime.
        if ($Accepted) { { & $runtimeGuard $value } | Should -Not -Throw }
        else { { & $runtimeGuard $value } | Should -Throw '*PowerShell 7.6 or later*' }
    }
    It 'accepts the actual reviewed running Core runtime value without conversion' {
        $PSVersionTable.PSVersion.GetType().FullName | Should -BeExactly 'System.Management.Automation.SemanticVersion'
        $PSVersionTable.PSVersion.Major | Should -Be 7
        $PSVersionTable.PSVersion.Minor | Should -Be 6
        { & $runtimeGuard $PSVersionTable.PSVersion } | Should -Not -Throw
    }
}
