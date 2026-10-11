# Offline test fixture only. The Windows compiler is an existing Windows/.NET component.
function New-FakeGitHubCli {
    param([Parameter(Mandatory)][string]$Directory)
    if ([Microsoft.PowerShell.Telemetry.ApplicationInsightsTelemetry]::CanSendTelemetry) {
        throw 'Telemetry must be disabled before PowerShell starts'
    }
    if ($env:POWERSHELL_TELEMETRY_OPTOUT -ne '1' -or $env:DOTNET_CLI_TELEMETRY_OPTOUT -ne '1') {
        throw 'Both telemetry opt-out environment variables must be set before fixture execution.'
    }
    $null = [IO.Directory]::CreateDirectory($Directory)
    if ($IsWindows) {
        $compiler = @(
            (Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),
            (Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe')
        ) | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
        if (-not $compiler) { throw 'The offline Windows fixture requires the existing .NET Framework C# compiler; no compiler will be downloaded or installed.' }
        $executable = Join-Path $Directory 'gh-fixture.exe'
        $source = Join-Path $PSScriptRoot 'FakeGitHubCli.cs'
        $diagnostics = & $compiler /nologo /target:exe "/out:$executable" $source 2>&1
        if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($executable)) {
            throw "The synthetic Windows CLI fixture did not compile: $($diagnostics -join ' ')"
        }
        return $executable
    }
    $executable = Join-Path $Directory 'gh-fixture'
    $script = @'
#!/bin/sh
[ "$POWERSHELL_TELEMETRY_OPTOUT" = 1 ] && [ "$DOTNET_CLI_TELEMETRY_OPTOUT" = 1 ] || exit 98
case "$PASSKEY_TEST_CLI_MODE" in
    no-read) sleep 6; exit 0 ;;
    success)
        v=$(cat)
        [ "$v" = 'SYNTHETIC-INPUT' ] || exit 7
        printf 'SYNTHETIC-STDOUT'
        printf 'SYNTHETIC-STDERR' >&2
        exit 0 ;;
    failure) cat >/dev/null; printf 'SYNTHETIC-STDERR' >&2; exit 9 ;;
    inherited-pipes)
        cat >/dev/null
        sleep 6 &
        child=$!
        [ -n "$PASSKEY_TEST_CHILD_PID" ] || { kill "$child"; wait "$child"; exit 95; }
        printf '%s\n' "$child" > "$PASSKEY_TEST_CHILD_PID" || { kill "$child"; wait "$child"; exit 94; }
        exit 0 ;;
    record|'') cat >/dev/null; printf '%s\n' "$*" >> "$PASSKEY_TEST_CALLS"; exit 0 ;;
    *) exit 97 ;;
esac
'@
    [IO.File]::WriteAllText($executable, $script, [Text.UTF8Encoding]::new($false))
    [IO.File]::SetUnixFileMode($executable, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)
    return $executable
}

function Stop-FakeGitHubCliChild {
    param([Parameter(Mandatory)][string]$PidFile,
        [Parameter(Mandatory)][string]$ExpectedExecutablePath,
        [Parameter(Mandatory)][datetime]$EarliestStartUtc)
    if (-not [IO.File]::Exists($PidFile)) { return }
    $identity = [IO.File]::ReadAllLines($PidFile)
    $processId = 0
    if (-not $identity.Count -or -not [int]::TryParse($identity[0], [ref]$processId) -or $processId -le 0) {
        throw 'Synthetic fixture child tracking data is invalid.'
    }
    $process = $null; $cleaned = $false
    try {
        try { $process = [Diagnostics.Process]::GetProcessById($processId) }
        catch [ArgumentException] { $cleaned = $true; return } # The specifically tracked process has already exited.
        if ($process.HasExited) { $cleaned = $true; return }
        $start = $process.StartTime.ToUniversalTime()
        if ($start -lt $EarliestStartUtc.AddSeconds(-1) -or $process.MainModule.FileName -ine $ExpectedExecutablePath -or
            ($identity.Count -gt 1 -and $start.Ticks -ne [long]$identity[1])) {
            throw 'Refusing to terminate a process that does not match the synthetic fixture child.'
        }
        $process.Kill($true)
        if (-not $process.WaitForExit(3000)) { throw 'Synthetic fixture child did not exit during cleanup.' }
        $cleaned = $true
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        if ($cleaned) { [IO.File]::Delete($PidFile) }
    }
}
