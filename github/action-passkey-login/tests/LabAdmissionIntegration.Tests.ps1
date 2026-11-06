BeforeAll {
    . (Join-Path $PSScriptRoot '../.github/validation/LabController.ps1')
}

Describe 'Admission composition through the real API path guard (offline)' {
    BeforeAll {
        $savedEnvironment = @{}
        foreach ($name in @('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKFLOW_REF', 'GH_TOKEN')) {
            $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
        }
    }
    BeforeEach {
        $env:GITHUB_REPOSITORY = 'nathanmcnulty/action-passkey-login'
        $env:GITHUB_EVENT_NAME = 'workflow_dispatch'
        $env:GITHUB_REF = 'refs/heads/main'
        $env:GITHUB_SHA = 'c' * 40
        $env:GITHUB_RUN_ATTEMPT = '1'
        $env:GITHUB_WORKFLOW_REF = 'nathanmcnulty/action-passkey-login/.github/workflows/validate-lab-cookie.yml@refs/heads/main'
        $env:GH_TOKEN = 'synthetic-offline-token-not-a-credential'
        $script:admissionCalls = [Collections.Generic.List[string]]::new()
        $script:httpFailure = $false
        $script:routes = @(
            '/repos/nathanmcnulty/action-passkey-login/git/ref/heads/main'
            '/repos/nathanmcnulty/action-passkey-login/pulls/6'
            ('/repos/nathanmcnulty/research-passkeys/compare/' + ('b' * 40) + '...main')
            ('/repos/nathanmcnulty/research-passkeys/git/trees/' + ('b' * 40) + '?recursive=1')
            ('/repos/nathanmcnulty/action-passkey-login/git/commits/' + ('a' * 40))
            ('/repos/nathanmcnulty/action-passkey-login/git/trees/' + ('a' * 40) + '?recursive=1')
            ('/repos/nathanmcnulty/action-passkey-login/actions/workflows/ci.yml/runs?head_sha=' + ('a' * 40) + '&event=push&per_page=1')
            ('/repos/nathanmcnulty/research-passkeys/actions/workflows/passkey-ci.yml/runs?head_sha=' + ('b' * 40) + '&event=push&per_page=1')
            '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation'
            '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation/deployment-branch-policies?per_page=100'
        )
        # Only the HTTP boundary is mocked. Every fixture has the relevant native
        # GitHub JSON shape; identities and revisions are synthetic, not live data.
        Mock Invoke-RestMethod {
            param($Uri, $Headers, $MaximumRedirection, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
            $Uri | Should -BeLikeExactly 'https://api.github.com/repos/nathanmcnulty/*'
            $Headers.Authorization | Should -BeExactly 'Bearer synthetic-offline-token-not-a-credential'
            $Headers.Accept | Should -BeExactly 'application/vnd.github+json'
            $Headers.'X-GitHub-Api-Version' | Should -BeExactly '2022-11-28'
            $MaximumRedirection | Should -Be 0
            $ConnectionTimeoutSeconds | Should -Be 20
            $OperationTimeoutSeconds | Should -Be 30
            $path = ([string]$Uri).Substring('https://api.github.com'.Length)
            $script:admissionCalls.Add($path)
            if ($script:httpFailure) { throw 'synthetic sensitive HTTP failure detail' }
            $index = [Array]::IndexOf($script:routes, $path)
            switch ($index) {
                0 { return @{ object = @{ sha = 'c' * 40 } } }
                1 { return @{ state = 'open'; head = @{ sha = 'a' * 40; repo = @{ full_name = 'nathanmcnulty/action-passkey-login' } }; base = @{ ref = 'main'; repo = @{ full_name = 'nathanmcnulty/action-passkey-login' } } } }
                2 { return @{ status = 'ahead'; merge_base_commit = @{ sha = 'b' * 40 } } }
                3 { return @{ truncated = $false; tree = @(@{ path = 'github/action-passkey-login'; type = 'tree'; sha = 'e' * 40 }, @{ path = '.github/workflows/passkey-ci.yml'; type = 'blob'; sha = '8b53d7b6cbee6d9d1225521b0067fc702a25ab0a' }) } }
                4 { return @{ tree = @{ sha = 'e' * 40 } } }
                5 { return @{ truncated = $false; tree = @(@{ path = '.github/workflows/ci.yml'; type = 'blob'; sha = 'ca67148179b12d1f465b49a082ceb7a708984c83' }) } }
                6 { return @{ workflow_runs = @(@{ head_sha = 'a' * 40; path = '.github/workflows/ci.yml'; head_repository = @{ full_name = 'nathanmcnulty/action-passkey-login' }; event = 'push'; status = 'completed'; conclusion = 'success'; id = 101; run_attempt = 1 }) } }
                7 { return @{ workflow_runs = @(@{ head_sha = 'b' * 40; path = '.github/workflows/passkey-ci.yml'; head_repository = @{ full_name = 'nathanmcnulty/research-passkeys' }; event = 'push'; status = 'completed'; conclusion = 'success'; id = 102; run_attempt = 1 }) } }
                8 { return @{ name = 'passkey-validation'; protection_rules = @(@{ type = 'required_reviewers'; reviewers = @(@{ type = 'User'; reviewer = @{ id = 1 } }) }); deployment_branch_policy = @{ custom_branch_policies = $true; protected_branches = $false }; can_admins_bypass = $false } }
                9 { return @{ total_count = 1; branch_policies = @(@{ name = 'main'; type = 'branch' }) } }
                default { throw 'Unexpected HTTP fixture request; real network is forbidden.' }
            }
        }
    }
    AfterAll {
        foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
    }

    It 'admits all ten exact routes through actual admission and Read-LabApi in order' {
        $receipt = Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40)
        ($script:admissionCalls -join "`n") | Should -BeExactly ($script:routes -join "`n")
        Should -Invoke Invoke-RestMethod -Times 10 -Exactly
        $receipt.CandidateSha | Should -BeExactly ('a' * 40)
        $receipt.SourceSha | Should -BeExactly ('b' * 40)
        $receipt.ControllerSha | Should -BeExactly ('c' * 40)
        $receipt.ActionCi.RunId | Should -Be 101
        $receipt.CanonicalCi.RunId | Should -Be 102
        $receipt.IndependentReadback | Should -BeExactly 'RequiredNotYetRun'
    }

    It 'reproduces the original compare-path failure after exactly two HTTP reads' {
        $fixedRead = (Get-Command Read-LabApi).ScriptBlock
        try {
            # Exact legacy guard and HTTP body from the failed controller. This
            # regression fixture is local only and never replaces production code.
            Set-Item Function:Read-LabApi -Value {
                param([Parameter(Mandatory)][string]$Path)
                if ($Path -notmatch '^/repos/nathanmcnulty/(action-passkey-login|research-passkeys)/' -or $Path.Contains('..')) { throw 'Unexpected API target.' }
                try {
                    Invoke-RestMethod -Uri ('https://api.github.com' + $Path) -Headers @{
                        Authorization = "Bearer $env:GH_TOKEN"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28'
                    } -MaximumRedirection 0 -ConnectionTimeoutSeconds 20 -OperationTimeoutSeconds 30 -Verbose:$false -Debug:$false -ErrorAction Stop
                } catch { throw 'GitHub admission read failed; no candidate admitted.' }
            }
            { Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40) } | Should -Throw '*Unexpected API target*'
            ($script:admissionCalls -join "`n") | Should -BeExactly ($script:routes[0..1] -join "`n")
            Should -Invoke Invoke-RestMethod -Times 2 -Exactly
        } finally { Set-Item Function:Read-LabApi -Value $fixedRead }
    }

    It 'suppresses HTTP failure detail and stops admission immediately' {
        $script:httpFailure = $true
        { Invoke-LabAdmission ('a' * 40) ('b' * 40) '6' ('c' * 40) } | Should -Throw -ExpectedMessage 'GitHub admission read failed; no candidate admitted.'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'rejects route mutations before the HTTP boundary: <Case>' -ForEach @(
        @{ Case = 'absolute URL'; Path = 'https://api.github.com/repos/nathanmcnulty/action-passkey-login/pulls/6' }
        @{ Case = 'alternate host'; Path = '//evil.invalid/repos/nathanmcnulty/action-passkey-login/pulls/6' }
        @{ Case = 'alternate owner'; Path = '/repos/other/action-passkey-login/pulls/6' }
        @{ Case = 'alternate repo'; Path = '/repos/nathanmcnulty/other/pulls/6' }
        @{ Case = 'case variation'; Path = '/repos/NathanMcNulty/action-passkey-login/pulls/6' }
        @{ Case = 'wrong repo route'; Path = '/repos/nathanmcnulty/research-passkeys/pulls/6' }
        @{ Case = 'traversal'; Path = '/repos/nathanmcnulty/action-passkey-login/../research-passkeys/pulls/6' }
        @{ Case = 'encoded traversal'; Path = '/repos/nathanmcnulty/action-passkey-login/%2e%2e/pulls/6' }
        @{ Case = 'double encoded traversal'; Path = '/repos/nathanmcnulty/action-passkey-login/%252e%252e/pulls/6' }
        @{ Case = 'encoded slash'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls%2f6' }
        @{ Case = 'backslash'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls\6' }
        @{ Case = 'trailing slash'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/6/' }
        @{ Case = 'trailing newline'; Path = "/repos/nathanmcnulty/action-passkey-login/pulls/6`n" }
        @{ Case = 'trailing CRLF'; Path = "/repos/nathanmcnulty/action-passkey-login/pulls/6`r`n" }
        @{ Case = 'leading whitespace'; Path = ' /repos/nathanmcnulty/action-passkey-login/pulls/6' }
        @{ Case = 'fragment'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/6#x' }
        @{ Case = 'unexpected query'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/6?x=1' }
        @{ Case = 'zero PR'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/0' }
        @{ Case = 'padded PR'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/06' }
        @{ Case = 'overflow PR'; Path = '/repos/nathanmcnulty/action-passkey-login/pulls/1234567890' }
        @{ Case = 'wrong compare repo'; Path = ('/repos/nathanmcnulty/action-passkey-login/compare/' + ('b' * 40) + '...main') }
        @{ Case = 'two dot compare'; Path = ('/repos/nathanmcnulty/research-passkeys/compare/' + ('b' * 40) + '..main') }
        @{ Case = 'four dot compare'; Path = ('/repos/nathanmcnulty/research-passkeys/compare/' + ('b' * 40) + '....main') }
        @{ Case = 'alternate compare target'; Path = ('/repos/nathanmcnulty/research-passkeys/compare/' + ('b' * 40) + '...other') }
        @{ Case = 'uppercase SHA'; Path = ('/repos/nathanmcnulty/research-passkeys/compare/' + ('B' * 40) + '...main') }
        @{ Case = 'zero SHA'; Path = ('/repos/nathanmcnulty/research-passkeys/compare/' + ('0' * 40) + '...main') }
        @{ Case = 'mutable tree'; Path = '/repos/nathanmcnulty/research-passkeys/git/trees/main?recursive=1' }
        @{ Case = 'tree wrong recursion'; Path = ('/repos/nathanmcnulty/research-passkeys/git/trees/' + ('b' * 40) + '?recursive=0') }
        @{ Case = 'duplicate tree query'; Path = ('/repos/nathanmcnulty/research-passkeys/git/trees/' + ('b' * 40) + '?recursive=1&recursive=1') }
        @{ Case = 'CI reordered query'; Path = ('/repos/nathanmcnulty/action-passkey-login/actions/workflows/ci.yml/runs?event=push&head_sha=' + ('a' * 40) + '&per_page=1') }
        @{ Case = 'CI extra query'; Path = ('/repos/nathanmcnulty/action-passkey-login/actions/workflows/ci.yml/runs?head_sha=' + ('a' * 40) + '&event=push&per_page=1&x=1') }
        @{ Case = 'CI different event'; Path = ('/repos/nathanmcnulty/action-passkey-login/actions/workflows/ci.yml/runs?head_sha=' + ('a' * 40) + '&event=pull_request&per_page=1') }
        @{ Case = 'CI different workflow'; Path = ('/repos/nathanmcnulty/action-passkey-login/actions/workflows/passkey-ci.yml/runs?head_sha=' + ('a' * 40) + '&event=push&per_page=1') }
        @{ Case = 'different environment'; Path = '/repos/nathanmcnulty/action-passkey-login/environments/production' }
        @{ Case = 'policy extra query'; Path = '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation/deployment-branch-policies?per_page=100&page=2' }
        @{ Case = 'policy smaller page'; Path = '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation/deployment-branch-policies?per_page=1' }
    ) {
        { Read-LabApi $Path } | Should -Throw '*Unexpected API target*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
}
