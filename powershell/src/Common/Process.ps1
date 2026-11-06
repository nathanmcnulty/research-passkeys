function New-PasskeyExternalStartInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath,[Parameter(Mandatory)][string[]]$Arguments,[bool]$Windows=$IsWindows)
    $info=[System.Diagnostics.ProcessStartInfo]::new()
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.CreateNoWindow=$true
    if ($Windows -and [IO.Path]::GetExtension($FilePath) -ieq '.cmd') {
        # Windows Azure CLI normally ships az.cmd. Only its fixed token-query arguments
        # are admitted to cmd.exe; arbitrary shell syntax and expansion are refused.
        if ($FilePath -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_:\\/(). -]+\.cmd$' -or ($FilePath -replace '^.*[\\/]','') -ine 'az.cmd') {
            throw 'Unsupported Windows command-script path.'
        }
        foreach ($argument in $Arguments) {
            if ($argument -cnotmatch '^[A-Za-z0-9:/._=-]+$') { throw 'Unsafe Windows command-script argument.' }
        }
        $system=[Environment]::GetFolderPath([Environment+SpecialFolder]::System)
        if (-not $system) { $system='C:\Windows\System32' } # Pure construction tests on non-Windows hosts.
        $info.FileName=[IO.Path]::Combine($system,'cmd.exe')
        $command='""'+$FilePath+'" '+(($Arguments | ForEach-Object {'"'+$_+'"'}) -join ' ')+'"'
        # cmd.exe consumes a raw Windows command line, not C-runtime argv quoting.
        # ArgumentList would escape these quotes with backslashes and break /s /c.
        # The path and every argument were restricted above before this construction.
        $info.Arguments='/d /s /c '+$command
    } else {
        $info.FileName=$FilePath
        foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    }
    return $info
}

function Invoke-PasskeyExternalCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath,[Parameter(Mandatory)][string[]]$Arguments,[ValidateRange(1,120)][int]$TimeoutSeconds=30)
    $process=[System.Diagnostics.Process]::new()
    $process.StartInfo=New-PasskeyExternalStartInfo -FilePath $FilePath -Arguments $Arguments
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $timeout=$TimeoutSeconds*1000
    try {
        if (-not $process.Start()) { throw 'External command could not start.' }
        $outputTask=$process.StandardOutput.ReadToEndAsync()
        $errorTask=$process.StandardError.ReadToEndAsync()
        $remaining=[Math]::Max(0,$timeout-[int]$clock.ElapsedMilliseconds)
        if (-not $process.WaitForExit($remaining)) { throw 'External command timed out.' }
        # Descendants can keep inherited pipes open after the original process exits.
        # Bound draining by the same deadline instead of waiting indefinitely on GetResult.
        $drain=[System.Threading.Tasks.Task]::WhenAll([System.Threading.Tasks.Task[]]@($outputTask,$errorTask))
        $remaining=[Math]::Max(0,$timeout-[int]$clock.ElapsedMilliseconds)
        if (-not $drain.Wait($remaining)) { throw 'External command stream draining timed out.' }
        $output=$outputTask.GetAwaiter().GetResult()
        $null=$errorTask.GetAwaiter().GetResult()
        return [pscustomobject]@{ExitCode=$process.ExitCode;Output=$output}
    } catch {
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch { }
        throw 'External command failed or timed out; details suppressed.'
    } finally {
        # Closing readers releases inherited pipe waits; do not log captured stderr.
        try { $process.StandardOutput.Dispose();$process.StandardError.Dispose() } catch { }
        $process.Dispose();$clock.Stop()
    }
}
