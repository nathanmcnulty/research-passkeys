function Wait-GitHubPasskeyCliTask {
    param([Parameter(Mandatory)][Threading.Tasks.Task]$Task,
        [Parameter(Mandatory)][Diagnostics.Stopwatch]$Clock,
        [Parameter(Mandatory)][int]$DeadlineMilliseconds)
    $remaining = [int][Math]::Max(0, $DeadlineMilliseconds - $Clock.ElapsedMilliseconds)
    if ($remaining -le 0 -or -not $Task.Wait($remaining)) { throw [TimeoutException]::new('CLI deadline exceeded.') }
}

function Invoke-GitHubPasskeyCli {
    # Child output is discarded; API diagnostics retain only a numeric HTTP status.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments, [AllowNull()][string]$InputText,
          [ValidateRange(1,300)][int]$TimeoutSeconds = 60, [switch]$CaptureHttpStatus)
    $check = if ($CaptureHttpStatus) { 'RepositoryAccess' } elseif ($Arguments[0] -eq 'secret') { 'SecretWrite' } else { 'Command' }
    $command = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        $PSCmdlet.ThrowTerminatingError((New-GitHubPasskeyCliError -Check $check -Category CommandMissing))
    }
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
    $category = 'StartFailed'; $httpStatus = $null; $exitCode = $null
    try {
        $null = $process.Start()
        $category = 'TransportFailure'
        # Copy to Stream.Null: never accumulate arbitrary child stdout/stderr in memory.
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stdout = if (-not $CaptureHttpStatus) { $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null) } else { $null }
        if ($null -ne $InputText) { Wait-GitHubPasskeyCliTask -Task ($process.StandardInput.WriteAsync($InputText)) -Clock $clock -DeadlineMilliseconds $deadlineMs }
        Wait-GitHubPasskeyCliTask -Task ($process.StandardInput.FlushAsync()) -Clock $clock -DeadlineMilliseconds $deadlineMs
        $process.StandardInput.Close()
        if ($CaptureHttpStatus) {
            # gh api --include --silent prints headers only. Read at most 128 bytes of
            # the first line, then discard everything else, even malformed CLI output.
            $prefix = [byte[]]::new(128); $count = 0
            while ($count -lt $prefix.Length) {
                $read = $process.StandardOutput.BaseStream.ReadAsync($prefix, $count, $prefix.Length - $count)
                Wait-GitHubPasskeyCliTask -Task $read -Clock $clock -DeadlineMilliseconds $deadlineMs
                if ($read.Result -eq 0) { break }
                $count += $read.Result
                if ([Array]::IndexOf($prefix, [byte]10, 0, $count) -ge 0) { break }
            }
            $line = [Text.Encoding]::ASCII.GetString($prefix, 0, $count).Split("`n")[0].TrimEnd("`r")
            if ($line -cmatch '^HTTP/[0-9.]+ ([1-5][0-9]{2})(?: |$)') { $httpStatus = [int]$matches[1] }
            $line = $null; $prefix = $null
        }
        if ($CaptureHttpStatus) { $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null) }
        $remaining = [int][Math]::Max(0, $deadlineMs - $clock.ElapsedMilliseconds)
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) { throw [TimeoutException]::new('CLI deadline exceeded.') }
        Wait-GitHubPasskeyCliTask -Task $stdout -Clock $clock -DeadlineMilliseconds $deadlineMs
        Wait-GitHubPasskeyCliTask -Task $stderr -Clock $clock -DeadlineMilliseconds $deadlineMs
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0 -or ($CaptureHttpStatus -and ($null -eq $httpStatus -or $httpStatus -lt 200 -or $httpStatus -ge 300))) {
            $category = if ($httpStatus -eq 401 -or $exitCode -eq 4) { 'AuthenticationFailed' }
                elseif ($httpStatus -eq 403) { 'AuthorizationDenied' }
                elseif ($httpStatus -eq 404) { 'RepositoryUnavailable' }
                elseif ($CaptureHttpStatus) { 'ApiFailure' } else { 'NonzeroExit' }
            throw 'CLI operation failed.'
        }
    } catch {
        if ($_.Exception -is [TimeoutException]) { $category = 'TimedOut' }
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch {}
        $PSCmdlet.ThrowTerminatingError((New-GitHubPasskeyCliError -Check $check -Category $category -HttpStatus $httpStatus -ExitCode $exitCode))
    }
    finally { $process.Dispose() }

}

function New-GitHubPasskeyCliError {
    param([ValidateSet('RepositoryAccess','SecretWrite','Command')][string]$Check,
        [ValidateSet('CommandMissing','StartFailed','TransportFailure','TimedOut','AuthenticationFailed','AuthorizationDenied','RepositoryUnavailable','ApiFailure','NonzeroExit')][string]$Category,
        [AllowNull()][object]$HttpStatus, [AllowNull()][object]$ExitCode)
    $status = [pscustomobject]@{ CliCheck = $Check; FailureCategory = $Category; HttpStatus = $HttpStatus; CliExitCode = $ExitCode }
    $message = "GitHub CLI operation failed or timed out. Check: $Check. Category: $Category. HTTP: $HttpStatus. Exit: $ExitCode. Raw output suppressed; a current secret write may be uncertain."
    [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($message), 'PasskeyGitHubCliFailed', [Management.Automation.ErrorCategory]::InvalidOperation, $status)
}

function Test-GitHubPasskeyDestination {
    param([Parameter(Mandatory)][string]$Repository)
    Assert-GitHubPasskeyRepository $Repository
    # Test the active credential's actual repository access. auth status checks unrelated
    # saved accounts on some gh versions and must not gate this operation.
    # Visibility is not a guarantee of later write permission.
    Invoke-GitHubPasskeyCli -Arguments @('api', '--hostname', 'github.com', '--include', '--silent', "repos/$Repository/actions/secrets?per_page=1") -CaptureHttpStatus
}

