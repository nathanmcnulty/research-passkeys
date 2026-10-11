BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $workflow = [System.IO.File]::ReadAllText((Join-Path $root '.github/workflows/passkey-ci.yml')).Replace("`r`n", "`n")

    function Get-WorkflowRunBlock {
        param([string]$StepName)
        $pattern = '(?ms)^      - name: ' + [regex]::Escape($StepName) + '\n.*?^        run: \|\n(?<body>(?:          [^\n]*\n|\n)+)'
        $match = [regex]::Match($workflow, $pattern)
        if (-not $match.Success) { throw "Missing workflow step: $StepName" }
        return [regex]::Replace($match.Groups['body'].Value, '(?m)^          ', '')
    }
}

Describe 'Credential-free passkey CI contract' {
    It 'runs pull requests, pushes and merge queues without path-filter skips' {
        $workflow | Should -Match '(?m)^  pull_request:'
        $workflow | Should -Match '(?m)^  push:'
        $workflow | Should -Match '(?m)^  merge_group:'
        $workflow | Should -Not -Match 'paths:|paths-ignore:|pull_request_target:'
    }

    It 'uses read-only permissions, a SHA-pinned checkout and no persisted credentials' {
        $workflow | Should -Match '(?m)^permissions:\n  contents: read$'
        $workflow | Should -Not -Match 'contents: write|pull-requests: write|secrets\.'
        $workflow | Should -Match 'uses: actions/checkout@[0-9a-f]{40}'
        $workflow | Should -Match 'fetch-depth: 0'
        $workflow | Should -Match 'persist-credentials: false'
    }

    It 'disables runtime telemetry before starting any PowerShell process' {
        $workflow | Should -Match "(?m)^env:\n  POWERSHELL_TELEMETRY_OPTOUT: '1'\n  DOTNET_CLI_TELEMETRY_OPTOUT: '1'$"
        $workflow.IndexOf('POWERSHELL_TELEMETRY_OPTOUT') | Should -BeLessThan $workflow.IndexOf('jobs:')
        $workflow | Should -Match 'ApplicationInsightsTelemetry\]::CanSendTelemetry'
        $workflow | Should -Match 'Telemetry must be disabled before PowerShell starts'
        $workflow.IndexOf('ApplicationInsightsTelemetry') | Should -BeLessThan $workflow.IndexOf('Check deterministic artifacts')
    }

    It 'installs and verifies the official exact PowerShell runtime before project checks' {
        $workflow | Should -Match 'https://github.com/PowerShell/PowerShell/releases/download/v7\.6\.6/powershell-7\.6\.6-linux-x64.tar.gz'
        $workflow | Should -Match 'DDBC4A2D113BBD46D283CFEDCBCD117A70CAEFD7673F41F2B4E0000BADF103BC'
        $workflow | Should -Match 'sha256sum --check --strict'
        $workflow | Should -Match "PSVersion -ne \[version\]'7\.6\.6'"
        $workflow.IndexOf('Install pinned PowerShell runtime') | Should -BeLessThan $workflow.IndexOf('Check deterministic artifacts')
    }

    It 'only checks output and uses the exact pinned Pester version from the official registry' {
        $workflow | Should -Match 'run: ./build/build.ps1 -Check'
        $workflow | Should -Not -Match '(?m)^        run: ./build/build.ps1\s*$|git push|git commit'
        $workflow | Should -Match 'Install-PSResource -Name Pester -Version 6\.2\.0 -Repository PSGallery'
        $workflow | Should -Match "Run.Path = @\('\.'\)"
        $workflow | Should -Match 'SkippedCount -gt 0'
        $workflow | Should -Match 'NotRunCount -gt 0'
    }

    It 'uses the default branch rather than an old root for a new-branch push' {
        $script = Get-WorkflowRunBlock 'Check deliberate source version'
        $oldBase = $env:BASE_SHA
        $oldDefault = $env:DEFAULT_BRANCH
        try {
            $env:BASE_SHA = '0000000000000000000000000000000000000000'
            $env:DEFAULT_BRANCH = 'main'
            Mock git { 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
            # Resolve only the base-selection AST, without invoking the version gate.
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            $body = @($ast.EndBlock.Statements)[0..1] | ForEach-Object { $_.Extent.Text }
            $global:LASTEXITCODE = 0
            . ([scriptblock]::Create($body -join "`n"))
            $baseRef | Should -Be 'refs/remotes/origin/main'
            Should -Invoke git -Times 1 -Exactly
        } finally {
            $env:BASE_SHA = $oldBase
            $env:DEFAULT_BRANCH = $oldDefault
        }
    }

    It 'always runs a stable aggregate check that rejects every non-success dependency' -ForEach @('success', 'failure', 'skipped', 'cancelled') {
        $workflow | Should -Match '(?m)^  passkey-ci:'
        $workflow | Should -Match '(?m)^    name: passkey-ci$'
        $workflow | Should -Match 'if: \$\{\{ always\(\) \}\}'
        $aggregate = [scriptblock]::Create((Get-WorkflowRunBlock 'Require every dependency to succeed'))
        $oldResults = $env:JOB_RESULTS
        try {
            $env:JOB_RESULTS = @{ 'build-and-test' = @{ result = $_ } } | ConvertTo-Json -Compress
            if ($_ -eq 'success') { { & $aggregate } | Should -Not -Throw }
            else { { & $aggregate } | Should -Throw '*Required job*' }
        } finally {
            $env:JOB_RESULTS = $oldResults
        }
    }
}

Describe 'Action distribution CI contract' {
    BeforeAll {
        $distributionWorkflow = [IO.File]::ReadAllText((Join-Path $root 'github/action-passkey-login/.github/workflows/ci.yml')).Replace("`r`n", "`n")
    }

    It 'preserves the push/pull-request offline job and read-only credential boundaries' {
        $distributionWorkflow | Should -Match '(?m)^on: \[push, pull_request\]$'
        $distributionWorkflow | Should -Match '(?m)^  test:$'
        $distributionWorkflow | Should -Match '(?m)^permissions:\n  contents: read$'
        $distributionWorkflow | Should -Match 'persist-credentials: false'
        $distributionWorkflow | Should -Match 'uses: actions/checkout@[0-9a-f]{40}'
        $distributionWorkflow | Should -Not -Match 'paths:|paths-ignore:|secrets\.|pull_request_target|contents: write'
    }

    It 'uses the same verified current runtime, dependency and telemetry guard as the source CI' {
        $distributionWorkflow | Should -Match 'releases/download/v7\.6\.6/powershell-7\.6\.6-linux-x64.tar.gz'
        $distributionWorkflow | Should -Match 'DDBC4A2D113BBD46D283CFEDCBCD117A70CAEFD7673F41F2B4E0000BADF103BC'
        $distributionWorkflow | Should -Match 'sha256sum --check --strict'
        $distributionWorkflow | Should -Match "PSVersion -ne \[version\]'7\.6\.6'"
        $distributionWorkflow | Should -Match "(?m)^env:\n  POWERSHELL_TELEMETRY_OPTOUT: '1'\n  DOTNET_CLI_TELEMETRY_OPTOUT: '1'$"
        $distributionWorkflow | Should -Match 'ApplicationInsightsTelemetry\]::CanSendTelemetry'
        $distributionWorkflow | Should -Match 'Install-PSResource -Name Pester -Version 6\.2\.0 -Repository PSGallery'
        $distributionWorkflow | Should -Not -Match '5\.7\.1|SkipPublisherCheck|Set-PSRepository'
    }

    It 'runs the standalone distribution test tree and rejects failures, skips and empty runs' {
        $distributionWorkflow | Should -Match "Run.Path = @\('\./tests'\)"
        foreach ($counter in @('FailedCount', 'SkippedCount', 'NotRunCount')) {
            $distributionWorkflow | Should -Match ([regex]::Escape($counter) + ' -gt 0')
        }
        $distributionWorkflow | Should -Match "Result -ne 'Passed'"
        $distributionWorkflow | Should -Match 'TotalCount -eq 0'
        $distributionWorkflow.IndexOf('ApplicationInsightsTelemetry') | Should -BeLessThan $distributionWorkflow.IndexOf('Run offline distribution tests')
    }
}
