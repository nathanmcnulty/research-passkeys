function Wait-GitHubPasskeyCliTask {
    param([Parameter(Mandatory)][Threading.Tasks.Task]$Task,
        [Parameter(Mandatory)][Diagnostics.Stopwatch]$Clock,
        [Parameter(Mandatory)][int]$DeadlineMilliseconds)
    $remaining = [int][Math]::Max(0, $DeadlineMilliseconds - $Clock.ElapsedMilliseconds)
    if ($remaining -le 0 -or -not $Task.Wait($remaining)) { throw 'CLI deadline exceeded.' }
}

function Invoke-GitHubPasskeyCli {
    # Child output is drained and discarded. Never forward gh stderr or exception details.
    param([Parameter(Mandatory)][string[]]$Arguments, [AllowNull()][string]$InputText,
          [ValidateRange(1,300)][int]$TimeoutSeconds = 60)
    $command = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { throw 'GitHub CLI (gh) is required; install it from its official source.' }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $command.Source
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $psi.Environment['GH_HOST'] = 'github.com'
    $psi.Environment['GH_PROMPT_DISABLED'] = '1'
    foreach ($arg in $Arguments) { $psi.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $deadlineMs = $TimeoutSeconds * 1000
    try {
        $null = $process.Start()
        # Copy to Stream.Null: never accumulate arbitrary child stdout/stderr in memory.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        if ($null -ne $InputText) { Wait-GitHubPasskeyCliTask -Task ($process.StandardInput.WriteAsync($InputText)) -Clock $clock -DeadlineMilliseconds $deadlineMs }
        Wait-GitHubPasskeyCliTask -Task ($process.StandardInput.FlushAsync()) -Clock $clock -DeadlineMilliseconds $deadlineMs
        $process.StandardInput.Close()
        $remaining = [int][Math]::Max(0, $deadlineMs - $clock.ElapsedMilliseconds)
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) { throw 'CLI deadline exceeded.' }
        Wait-GitHubPasskeyCliTask -Task $stdout -Clock $clock -DeadlineMilliseconds $deadlineMs
        Wait-GitHubPasskeyCliTask -Task $stderr -Clock $clock -DeadlineMilliseconds $deadlineMs
        if ($process.ExitCode -ne 0) { throw 'CLI operation failed.' }
    } catch {
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch {}
        throw 'GitHub CLI operation failed or timed out; raw output was suppressed and the current write may be uncertain.'
    }
    finally { $process.Dispose() }

}

function Test-GitHubPasskeyDestination {
    param([Parameter(Mandatory)][string]$Repository)
    Assert-GitHubPasskeyRepository $Repository
    Invoke-GitHubPasskeyCli -Arguments @('auth','status','--hostname','github.com')
    # A read-only preflight checks visibility, not a guarantee of later write permission.
    Invoke-GitHubPasskeyCli -Arguments @('api', '--hostname', 'github.com', "repos/$Repository/actions/secrets?per_page=1")
}

