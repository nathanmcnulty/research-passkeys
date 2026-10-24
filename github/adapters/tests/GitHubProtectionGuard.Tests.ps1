BeforeAll {
    $repo = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    . "$repo/powershell/src/Common/Values.ps1"
    . "$repo/powershell/src/GitHub/SecretValues.ps1"
    . "$repo/powershell/src/GitHub/Transport.ps1"
    . "$PSScriptRoot/fixtures/New-FakeGitHubCli.ps1"
    $script:oldMode = $env:PASSKEY_TEST_CLI_MODE
    $script:fakeGh = New-FakeGitHubCli -Directory (Join-Path $TestDrive 'sentinel-cli')
    $script:jq = Get-Command jq -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
}
AfterAll { $env:PASSKEY_TEST_CLI_MODE = $script:oldMode }
Describe 'Bounded protection sentinel transport' {
    BeforeEach { Mock Get-Command { [pscustomobject]@{ Source = $script:fakeGh } } -ParameterFilter { $Name -eq 'gh' } }
    It 'accepts only a successful exact sentinel with LF or CRLF and emits no output' -ForEach @('sentinel-ok','sentinel-crlf') {
        $env:PASSKEY_TEST_CLI_MODE = $_
        Invoke-GitHubPasskeyCli -Arguments @('synthetic') -RequireProtectionSentinel | Should -BeNullOrEmpty
    }
    It 'rejects empty extra oversized unterminated and failed output without exposing any raw text' -ForEach @('sentinel-empty','sentinel-extra','sentinel-huge','sentinel-prefix','sentinel-failed') {
        $env:PASSKEY_TEST_CLI_MODE = $_; $caught = $null
        try { Invoke-GitHubPasskeyCli -Arguments @('synthetic') -RequireProtectionSentinel } catch { $caught = $_ }
        $caught.TargetObject.FailureCategory | Should -BeExactly ProtectionRejected
        $caught.TargetObject.CliCheck | Should -BeExactly EnvironmentProtection
        ($caught | Out-String) | Should -Not -Match 'SYNTHETIC|PASSKEY_PROTECTION_OK'
        $safe = New-PasskeyOperationError -Stage GitHubPreflight -ProtectedLab -CliFailure $caught.TargetObject
        $safe.TargetObject.CliCheck | Should -BeExactly EnvironmentProtection
        $safe.TargetObject.FailureCategory | Should -BeExactly ProtectionRejected
    }
    It 'bounds a child that produces no output and never exits' {
        $env:PASSKEY_TEST_CLI_MODE = 'no-read'
        { Invoke-GitHubPasskeyCli -Arguments @('synthetic') -RequireProtectionSentinel -TimeoutSeconds 1 } | Should -Throw '*TimedOut*'
    }
}
Describe 'Fixed protection predicates evaluated against synthetic JSON only' {
    BeforeEach {
        if (-not $script:jq) { throw 'Offline protection predicate tests require an existing jq executable; tests never install it.' }
        $script:queries = [Collections.Generic.List[string]]::new()
        Mock Invoke-GitHubPasskeyCli {
            $RequireProtectionSentinel | Should -BeTrue
            $Arguments | Should -Not -Contain '--silent'
            $Arguments | Should -Contain 'GET'
            $script:queries.Add($Arguments[-1])
        }
        Test-GitHubPasskeyDestination -Repository owner/repo -ProtectedLab -Environment passkey-validation
        $script:environment = @{ name = 'passkey-validation'; protection_rules = @(@{ type = 'required_reviewers'; reviewers = @(@{ type = 'User'; reviewer = @{ id = 123 } }) }); deployment_branch_policy = @{ custom_branch_policies = $true; protected_branches = $false }; can_admins_bypass = $false }
        $script:branches = @{ total_count = 1; branch_policies = @(@{ name = 'main'; type = 'branch' }) }
    }
    It 'accepts exact reviewer and selected-main policy JSON' {
        foreach ($i in 0,1) {
            $value = if ($i -eq 0) { $script:environment } else { $script:branches }
            $result = ($value | ConvertTo-Json -Depth 20 -Compress) | & $script:jq.Source -r $script:queries[$i] 2>$null
            $LASTEXITCODE | Should -Be 0
            @($result).Count | Should -Be 1
            $result | Should -BeExactly PASSKEY_PROTECTION_OK
        }
    }
    It 'rejects malformed or missing reviewer/protection fields' -ForEach @('empty','null-reviewer','fraction-id','string-id','zero-id','null-rule','missing-rules','wrong-rules','wrong-reviewers','wrong-name','string-bool','bypass','null-bypass','missing-policy','duplicate-rule','wrong-reviewer-type') {
        switch ($_) {
            empty { $script:environment.protection_rules[0].reviewers = @() }
            null-reviewer { $script:environment.protection_rules[0].reviewers = @($null) }
            fraction-id { $script:environment.protection_rules[0].reviewers[0].reviewer.id = 1.5 }
            string-id { $script:environment.protection_rules[0].reviewers[0].reviewer.id = '123' }
            zero-id { $script:environment.protection_rules[0].reviewers[0].reviewer.id = 0 }
            null-rule { $script:environment.protection_rules = @($null) }
            missing-rules { $script:environment.Remove('protection_rules') }
            wrong-rules { $script:environment.protection_rules = 'required_reviewers' }
            wrong-reviewers { $script:environment.protection_rules[0].reviewers = @{ type = 'User'; reviewer = @{ id = 123 } } }
            wrong-name { $script:environment.name = 'other' }
            string-bool { $script:environment.deployment_branch_policy.custom_branch_policies = 'true' }
            bypass { $script:environment.can_admins_bypass = $true }
            null-bypass { $script:environment.can_admins_bypass = $null }
            missing-policy { $script:environment.Remove('deployment_branch_policy') }
            duplicate-rule { $script:environment.protection_rules += $script:environment.protection_rules[0] }
            wrong-reviewer-type { $script:environment.protection_rules[0].reviewers[0].type = 'Bot' }
        }
        $result = ($script:environment | ConvertTo-Json -Depth 20 -Compress) | & $script:jq.Source -r $script:queries[0] 2>$null
        @($result) | Should -Not -Contain PASSKEY_PROTECTION_OK
        $LASTEXITCODE | Should -Not -Be 0
    }
    It 'rejects every nonexclusive-main branch shape' -ForEach @('extra','empty','missing','string-count','wildcard','tag','wrong-array','null-entry') {
        switch ($_) {
            extra { $script:branches.total_count = 2; $script:branches.branch_policies += @{ name = '*'; type = 'branch' } }
            empty { $script:branches.branch_policies = @() }
            missing { $script:branches.Remove('total_count') }
            string-count { $script:branches.total_count = '1' }
            wildcard { $script:branches.branch_policies[0].name = '*' }
            tag { $script:branches.branch_policies[0].type = 'tag' }
            wrong-array { $script:branches.branch_policies = @{ name = 'main'; type = 'branch' } }
            null-entry { $script:branches.branch_policies = @($null) }
        }
        $result = ($script:branches | ConvertTo-Json -Depth 20 -Compress) | & $script:jq.Source -r $script:queries[1] 2>$null
        @($result) | Should -Not -Contain PASSKEY_PROTECTION_OK
        $LASTEXITCODE | Should -Not -Be 0
    }
}
