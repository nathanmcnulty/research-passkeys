BeforeAll {
    . (Join-Path $PSScriptRoot '../.github/validation/LabController.ps1')
    $sha = 'a' * 40
}

Describe 'Lab admission primitives (no live calls)' {
    BeforeAll { Mock Invoke-RestMethod { throw 'Network is forbidden in offline controller tests.' } }
    It 'accepts only the trusted manual repository main with full immutable inputs' {
        { Assert-LabInputs 'nathanmcnulty/action-passkey-login' 'workflow_dispatch' 'refs/heads/main' $sha $sha '6' $sha } | Should -Not -Throw
    }
    It 'rejects an untrusted repository, event or ref' -ForEach @(
        @{ Repo = 'fork/action-passkey-login'; Event = 'workflow_dispatch'; Ref = 'refs/heads/main' },
        @{ Repo = 'nathanmcnulty/action-passkey-login'; Event = 'pull_request_target'; Ref = 'refs/heads/main' },
        @{ Repo = 'nathanmcnulty/action-passkey-login'; Event = 'workflow_dispatch'; Ref = 'refs/heads/topic' }
    ) {
        { Assert-LabInputs $Repo $Event $Ref $sha $sha '6' $sha } | Should -Throw
    }
    It 'rejects mutable, malformed and zero candidate revisions' -ForEach @('main', 'abc123', ('0' * 40), ('A' * 40), ('a' * 40 + ';echo bad'), ('a' * 40 + "`n")) {
        { Assert-LabInputs 'nathanmcnulty/action-passkey-login' 'workflow_dispatch' 'refs/heads/main' $_ $sha '6' $sha } | Should -Throw
    }
    It 'requires an actual PR number' -ForEach @('0', '-1', '6/../../', 'x', "6`n") {
        { Assert-LabInputs 'nathanmcnulty/action-passkey-login' 'workflow_dispatch' 'refs/heads/main' $sha $sha $_ $sha } | Should -Throw
    }
    It 'rejects unexpected API origins before any network call' {
        { Read-LabApi 'https://example.com/' } | Should -Throw '*Unexpected API*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
}

Describe 'Existing environment protections' {
    BeforeEach {
        $environment = @{ name = 'passkey-validation'; protection_rules = @(@{ type = 'required_reviewers'; reviewers = @(@{ type = 'User'; reviewer = @{id = 1} }) }); deployment_branch_policy = @{ custom_branch_policies = $true; protected_branches = $false }; can_admins_bypass = $false }
        $policies = @{ total_count = 1; branch_policies = @(@{ name = 'main'; type = 'branch' }) }
    }
    It 'accepts reviewer-protected selected main only' { { Assert-LabEnvironment $environment $policies } | Should -Not -Throw }
    It 'rejects absent review' { $environment.protection_rules = @(); { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects empty reviewer lists' { $environment.protection_rules[0].reviewers = @(); { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects null reviewer entries' { $environment.protection_rules[0].reviewers = @($null); { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects missing reviewer identity' { $environment.protection_rules[0].reviewers[0].reviewer = $null; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects non-integer reviewer identities' -ForEach @('123', 1.5, $true) { $environment.protection_rules[0].reviewers[0].reviewer.id = $_; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects non-array protection rules' { $environment.protection_rules = $environment.protection_rules[0]; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects non-array reviewer collections' { $environment.protection_rules[0].reviewers = $environment.protection_rules[0].reviewers[0]; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects protected-branches-only configuration' { $environment.deployment_branch_policy.custom_branch_policies = $false; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects string policy booleans' { $environment.deployment_branch_policy.custom_branch_policies = 'true'; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects extra branch policies' { $policies.total_count = 2; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects string policy counts' { $policies.total_count = '1'; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects non-array branch collections' { $policies.branch_policies = $policies.branch_policies[0]; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects array branch names' { $policies.branch_policies[0].name = @('main'); { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects tag admission' { $policies.branch_policies[0].type = 'tag'; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects wildcard admission' { $policies.branch_policies[0].name = '*'; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects visible administrator bypass' { $environment.can_admins_bypass = $true; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects a malformed bypass flag' { $environment.can_admins_bypass = 'false'; { Assert-LabEnvironment $environment $policies } | Should -Throw }
    It 'rejects present null bypass configuration' { $environment.can_admins_bypass = $null; { Assert-LabEnvironment $environment $policies } | Should -Throw }
}

Describe 'Exact latest offline CI result' {
    BeforeEach {
        $run = @{ head_sha = $sha; path = '.github/workflows/ci.yml'; event = 'push'; head_repository = @{ full_name = 'nathanmcnulty/action-passkey-login' }; status = 'completed'; conclusion = 'success'; id = 123; run_attempt = 2 }
    }
    It 'records exact successful run identity and attempt' {
        $result = Assert-LabCi @{workflow_runs = @($run)} 'nathanmcnulty/action-passkey-login' $sha '.github/workflows/ci.yml'
        $result.RunId | Should -Be 123
        $result.Attempt | Should -Be 2
    }
    It 'does not accept absent CI' { { Assert-LabCi @{workflow_runs = @()} 'nathanmcnulty/action-passkey-login' $sha '.github/workflows/ci.yml' } | Should -Throw }
    It 'rejects non-success latest runs' -ForEach @('failure', 'cancelled', 'skipped', '') {
        $run.conclusion = $_
        { Assert-LabCi @{workflow_runs = @($run)} 'nathanmcnulty/action-passkey-login' $sha '.github/workflows/ci.yml' } | Should -Throw
    }
    It 'rejects queued evidence despite a success label' { $run.status = 'queued'; { Assert-LabCi @{workflow_runs = @($run)} 'nathanmcnulty/action-passkey-login' $sha '.github/workflows/ci.yml' } | Should -Throw }
    It 'rejects the wrong workflow, revision, event or repository' -ForEach @('path', 'head_sha', 'event', 'repository') {
        if ($_ -eq 'repository') { $run.head_repository.full_name = 'fork/repo' } else { $run[$_] = 'wrong' }
        { Assert-LabCi @{workflow_runs = @($run)} 'nathanmcnulty/action-passkey-login' $sha '.github/workflows/ci.yml' } | Should -Throw
    }
}

Describe 'Cookie contract is strictly narrower than identity verification' {
    It 'accepts the explicit synthetic valid contract' {
        { Assert-LabCookieContract 'true' 'offline-placeholder' 'ESTSAUTH' 'Local Private Key' 'test@example.invalid' 'test@example.invalid' } | Should -Not -Throw
    }
    It 'rejects missing/invalid outputs without echoing supplied values' -ForEach @('Authenticated', 'Cookie', 'CookieName', 'Method', 'ReturnedUpn', 'RequestedUpn') {
        $values = @{Authenticated = 'true'; Cookie = 'offline-secret-placeholder'; CookieName = 'ESTSAUTH'; Method = 'Local Private Key'; RequestedUpn = 'test@example.invalid'; ReturnedUpn = 'test@example.invalid'}
        $values[$_] = ''
        { Assert-LabCookieContract @values } | Should -Throw '*sensitive values suppressed*'
    }
}

Describe 'Manual workflow trust boundary' {
    BeforeAll { $workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/validate-lab-cookie.yml') -Raw }
    It 'uses only manual invocation, no OIDC or write permissions' {
        $workflow | Should -Match 'workflow_dispatch:'
        $workflow | Should -Not -Match 'pull_request_target:|workflow_run:|id-token:|: write|upload-artifact|actions/cache'
        $workflow | Should -Match 'environment: passkey-validation'
        $workflow | Should -Match 'cancel-in-progress: false'
    }
    It 'keeps candidate secrets in new lab names and never legacy names' {
        $workflow | Should -Not -Match 'PASSKEY_PRIVATE_'
        foreach ($name in @('CREDENTIAL_ID', 'USER_HANDLE', 'USER_PRINCIPAL_NAME', 'PRIVATE_KEY')) { $workflow | Should -Match "PASSKEY_LAB_$name" }
    }
    It 'rechecks admission before candidate checkout and cannot produce an overall live pass' {
        ([regex]::Matches($workflow, 'Invoke-LabAdmission')).Count | Should -Be 2
        $workflow.IndexOf('Recheck admission after environment approval') | Should -BeLessThan $workflow.IndexOf('Check out admitted candidate')
        $workflow | Should -Match 'independent-readback-not-implemented:'
        $workflow | Should -Match 'exit 1'
    }
    It 'does not interpolate expressions into shell source' {
        foreach ($match in [regex]::Matches($workflow, '(?ms)^        run: \|\r?\n(?<body>(?:          [^\n]*\n|\n)+)')) {
            $match.Groups['body'].Value | Should -Not -Match '\$\{\{'
        }
    }
}

Describe 'Admission uses only mocked API evidence' {
    BeforeAll {
        $saved = @{}
        foreach ($name in @('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKFLOW_REF')) {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name)
        }
    }
    BeforeEach {
        $env:GITHUB_REPOSITORY = 'nathanmcnulty/action-passkey-login'
        $env:GITHUB_EVENT_NAME = 'workflow_dispatch'
        $env:GITHUB_REF = 'refs/heads/main'
        $env:GITHUB_SHA = 'c' * 40
        $env:GITHUB_RUN_ATTEMPT = '1'
        $env:GITHUB_WORKFLOW_REF = 'nathanmcnulty/action-passkey-login/.github/workflows/validate-lab-cookie.yml@refs/heads/main'
        $script:labFault = ''
        Mock Invoke-RestMethod { throw 'Real network is forbidden.' }
        Mock Read-LabApi {
            param($Path)
            if ($script:labFault -eq 'api') { throw 'Offline simulated API failure.' }
            switch -Wildcard ($Path) {
                '*/git/ref/heads/main' { return @{object = @{sha = $(if ($script:labFault -eq 'main') {'d' * 40} else {'c' * 40})}} }
                '*/pulls/6' { return @{state = 'open'; head = @{sha = $(if ($script:labFault -eq 'head') {'d' * 40} else {'a' * 40}); repo = @{full_name = 'nathanmcnulty/action-passkey-login'}}; base = @{ref = 'main'; repo = @{full_name = 'nathanmcnulty/action-passkey-login'}}} }
                '*/compare/*' { return @{status = $(if ($script:labFault -eq 'ancestry') {'diverged'} else {'ahead'}); merge_base_commit = @{sha = 'b' * 40}} }
                '*/research-passkeys/git/trees/*' { return @{truncated = ($script:labFault -eq 'truncated'); tree = @(@{path = 'github/action-passkey-login'; type = 'tree'; sha = 'e' * 40}, @{path = '.github/workflows/passkey-ci.yml'; type = 'blob'; sha = '8b53d7b6cbee6d9d1225521b0067fc702a25ab0a'})} }
                '*/action-passkey-login/git/commits/*' { return @{tree = @{sha = $(if ($script:labFault -eq 'mirror') {'f' * 40} else {'e' * 40})}} }
                '*/action-passkey-login/git/trees/*' { return @{truncated = $false; tree = @(@{path = '.github/workflows/ci.yml'; type = 'blob'; sha = $(if ($script:labFault -eq 'ci-blob') {'f' * 40} else {'ca67148179b12d1f465b49a082ceb7a708984c83'})})} }
                '*/actions/workflows/*' {
                    $isCanonical = $Path.Contains('/research-passkeys/')
                    return @{workflow_runs = @(@{
                        head_sha = $(if ($isCanonical) {'b' * 40} else {'a' * 40})
                        path = $(if ($isCanonical) {'.github/workflows/passkey-ci.yml'} else {'.github/workflows/ci.yml'})
                        head_repository = @{full_name = $(if ($isCanonical) {'nathanmcnulty/research-passkeys'} else {'nathanmcnulty/action-passkey-login'})}
                        event = 'push'; status = $(if ($script:labFault -eq 'pending-ci') {'in_progress'} else {'completed'})
                        conclusion = 'success'; id = 123; run_attempt = 1
                    })}
                }
                '*/environments/passkey-validation' { return @{name = 'passkey-validation'; protection_rules = @(@{type = 'required_reviewers'; reviewers = @(@{type = 'User'; reviewer = @{id = 1}})}); deployment_branch_policy = @{custom_branch_policies = $true; protected_branches = $false}; can_admins_bypass = $false} }
                '*/deployment-branch-policies*' { return @{total_count = 1; branch_policies = @(@{name = $(if ($script:labFault -eq 'environment') {'*'} else {'main'}); type = 'branch'})} }
                default { throw 'Unexpected mocked API request.' }
            }
        }
    }
    AfterAll {
        foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
    }
    It 'produces only an allowlisted admission receipt from exact source and CI' {
        $receipt = Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40)
        $receipt.CandidateSha | Should -BeExactly ('a' * 40)
        $receipt.IndependentReadback | Should -BeExactly 'NotImplemented'
        $receipt.ActionCi.RunId | Should -Be 123
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
    It 'fails closed on <Fault>' -ForEach @('main', 'head', 'ancestry', 'truncated', 'mirror', 'ci-blob', 'pending-ci', 'environment', 'api') {
        $script:labFault = $_
        { Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40) } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
    It 'rejects reruns before API access' {
        $env:GITHUB_RUN_ATTEMPT = '2'
        { Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40) } | Should -Throw '*Reruns*'
        Should -Invoke Read-LabApi -Times 0 -Exactly
    }
    It 'rejects unexpected controller identity before API access' {
        $env:GITHUB_WORKFLOW_REF = 'nathanmcnulty/action-passkey-login/.github/workflows/other.yml@refs/heads/main'
        { Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40) } | Should -Throw '*workflow identity*'
        Should -Invoke Read-LabApi -Times 0 -Exactly
    }
}
