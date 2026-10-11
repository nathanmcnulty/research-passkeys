BeforeAll {
    $oldMode = $env:PASSKEY_TEST_CLI_MODE
    $oldChildPid = $env:PASSKEY_TEST_CHILD_PID
    $fakeGh = $null; $childExecutable = $null; $childPidFile = $null
    $fixtureStartUtc = [datetime]::UtcNow
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Export-PasskeyToGitHubSecret.ps1')
    . (Join-Path $PSScriptRoot 'fixtures/New-FakeGitHubCli.ps1')
    $childPidFile = Join-Path $TestDrive 'fixture-child.pid'
    $fakeGh = New-FakeGitHubCli -Directory (Join-Path $TestDrive 'native-gh')
    $childExecutable = if ($IsWindows) { $fakeGh } else { (Get-Command sleep -CommandType Application | Select-Object -First 1).Source }
    $env:PASSKEY_TEST_CHILD_PID = $childPidFile
}
AfterAll {
    try {
        if ($childPidFile -and $childExecutable) { Stop-FakeGitHubCliChild -PidFile $childPidFile -ExpectedExecutablePath $childExecutable -EarliestStartUtc $fixtureStartUtc }
    } finally {
        $env:PASSKEY_TEST_CLI_MODE = $oldMode
        $env:PASSKEY_TEST_CHILD_PID = $oldChildPid
    }
}
Describe 'Bounded stdin-only subprocess transport (native platform fixture)' {
    BeforeEach {
        $fixtureStartUtc = [datetime]::UtcNow
        Mock Get-Command { [pscustomobject]@{ Source = $fakeGh } } -ParameterFilter { $Name -eq 'gh' }
    }
    AfterEach { Stop-FakeGitHubCliChild -PidFile $childPidFile -ExpectedExecutablePath $childExecutable -EarliestStartUtc $fixtureStartUtc }
    It 'suppresses successful child stdout/stderr and sends exact stdin' {
        $env:PASSKEY_TEST_CLI_MODE = 'success'
        $result = Invoke-GitHubPasskeyCli -Arguments @('secret','set','FIXTURE') -InputText 'SYNTHETIC-INPUT'
        $result | Should -BeNullOrEmpty
    }
    It 'suppresses failed process output in errors' {
        $env:PASSKEY_TEST_CLI_MODE = 'failure'
        $errorText = $null
        try { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText 'SYNTHETIC-INPUT' } catch { $errorText = $_ | Out-String }
        $errorText | Should -Match 'failed or timed out'
        $errorText | Should -Not -Match 'SYNTHETIC'
    }
    It 'bounds process wait and stdin even if child never reads' {
        $env:PASSKEY_TEST_CLI_MODE = 'no-read'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText ('x' * 49152) -TimeoutSeconds 1 } | Should -Throw '*timed out*'
        $clock.Elapsed.TotalSeconds | Should -BeGreaterThan 0.8
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
    }
    It 'bounds inherited output-pipe drains after the parent exits' {
        $env:PASSKEY_TEST_CLI_MODE = 'inherited-pipes'
        # Cold Windows native startup has exceeded one second. Keep one fixed overall
        # deadline, with a bounded five-second startup allowance and one-second drain budget.
        # The fixture delays two seconds before spawning, so a fresh per-stage drain budget
        # cannot satisfy the same original-deadline upper bound, even on fast Linux.
        $startupAllowanceSeconds = 5
        $deadlineSeconds = $startupAllowanceSeconds + 1
        $invocationStartUtc = [datetime]::UtcNow
        $clock = [Diagnostics.Stopwatch]::StartNew()
        { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText 'synthetic' -TimeoutSeconds $deadlineSeconds } | Should -Throw '*timed out*'
        [IO.File]::Exists($childPidFile) | Should -BeTrue
        [IO.File]::Exists("$childPidFile.ready") | Should -BeTrue
        [IO.File]::GetLastWriteTimeUtc($childPidFile) | Should -BeLessThan $invocationStartUtc.AddSeconds($startupAllowanceSeconds)
        [IO.File]::GetLastWriteTimeUtc("$childPidFile.ready") | Should -BeLessThan $invocationStartUtc.AddSeconds($deadlineSeconds)
        $identity = [IO.File]::ReadAllLines($childPidFile)
        $identity.Count | Should -BeGreaterThan 2
        if ($IsWindows) { [IO.File]::ReadAllText("$childPidFile.ready").Trim() | Should -BeExactly $identity[0] }
        else { [IO.File]::ReadAllText("$childPidFile.ready").Trim() | Should -BeExactly 'ready' }
        $child = [Diagnostics.Process]::GetProcessById([int]$identity[0])
        try { $child.HasExited | Should -BeFalse } finally { $child.Dispose() }
        $parent = $null; $parentExited = $false
        try {
            try { $parent = [Diagnostics.Process]::GetProcessById([int]$identity[2]) }
            catch [ArgumentException] { $parentExited = $true }
            if ($null -ne $parent) { $parentExited = $parent.HasExited }
            $parentExited | Should -BeTrue
        } finally { if ($null -ne $parent) { $parent.Dispose() } }
        $clock.Elapsed.TotalSeconds | Should -BeGreaterThan ($deadlineSeconds - 0.2)
        $clock.Elapsed.TotalSeconds | Should -BeLessThan ($deadlineSeconds + 1)
    }
}
