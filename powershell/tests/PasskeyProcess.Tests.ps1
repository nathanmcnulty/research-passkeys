BeforeAll { . "$PSScriptRoot/../src/Common/Process.ps1" }
Describe 'Bounded CLI process and stream handling' {
    It 'passes arguments directly without a shell on ordinary executables' {
        $info=New-PasskeyExternalStartInfo -FilePath '/bin/example' -Arguments @('a b','literal&value') -Windows:$false
        $info.FileName | Should -BeExactly '/bin/example'
        @($info.ArgumentList) | Should -Be @('a b','literal&value')
        $info.UseShellExecute | Should -BeFalse
    }
    It 'constructs the bounded Windows az.cmd route with no expansion or arbitrary shell input' {
        $info=New-PasskeyExternalStartInfo -FilePath 'C:\Program Files\Azure CLI\az.cmd' -Arguments @('account','get-access-token','--resource','https://vault.azure.net','--output','json') -Windows:$true
        $info.FileName | Should -Match '[/\\]cmd.exe$'
        @($info.ArgumentList).Count | Should -Be 0
        $info.Arguments | Should -BeExactly '/d /s /c ""C:\Program Files\Azure CLI\az.cmd" "account" "get-access-token" "--resource" "https://vault.azure.net" "--output" "json""'
        foreach ($argument in @('x&calc','x|calc','%TOKEN%','!TOKEN!','x"y','x^y',"x`ny")) {
            {New-PasskeyExternalStartInfo -FilePath 'C:\Azure\az.cmd' -Arguments @($argument) -Windows:$true} | Should -Throw '*Unsafe*'
        }
        {New-PasskeyExternalStartInfo -FilePath 'C:\Azure\other.cmd' -Arguments @('account') -Windows:$true} | Should -Throw '*Unsupported*'
    }
    It 'runs a synthetic az.cmd with ordinary and space-containing Windows paths' -ForEach @('ordinary','space (folder)') {
        if ($IsWindows) {
            $directory=Join-Path $TestDrive $_
            $null=New-Item -ItemType Directory -Path $directory -Force
            $file=Join-Path $directory 'az.cmd'
            $fixture=@'
@echo off
if not "%~1"=="account" exit /b 21
if not "%~2"=="get-access-token" exit /b 22
if not "%~3"=="--resource" exit /b 23
if not "%~4"=="https://vault.azure.net" exit /b 24
if not "%~5"=="--output" exit /b 25
if not "%~6"=="json" exit /b 26
if not "%~7"=="" exit /b 27
echo synthetic-cli-output
echo SYNTHETIC-SECRET 1>&2
exit /b 0
'@
            [IO.File]::WriteAllText($file,($fixture.Replace("`r`n","`n").Replace("`n","`r`n")+"`r`n"),[Text.UTF8Encoding]::new($false))
            $result=Invoke-PasskeyExternalCommand -FilePath $file -Arguments @('account','get-access-token','--resource','https://vault.azure.net','--output','json') -TimeoutSeconds 5
            $result.ExitCode | Should -Be 0
            $result.Output.Trim() | Should -BeExactly 'synthetic-cli-output'
            $result | ConvertTo-Json | Should -Not -Match 'SYNTHETIC-SECRET'
        } else {
            # Linux CI cannot execute cmd.exe, but exercises the same exact constructor.
            $file='C:\fixtures\'+$_+'\az.cmd'
            $info=New-PasskeyExternalStartInfo -FilePath $file -Arguments @('account','get-access-token') -Windows:$true
            $info.Arguments | Should -BeExactly ('/d /s /c ""'+$file+'" "account" "get-access-token""')
            @($info.ArgumentList).Count | Should -Be 0
        }
    }
    It 'bounds both running processes and inherited descendant pipes under one deadline' {
        $pwsh=(Get-Process -Id $PID).Path
        $clock=[Diagnostics.Stopwatch]::StartNew()
        {Invoke-PasskeyExternalCommand -FilePath $pwsh -Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 5') -TimeoutSeconds 1} | Should -Throw '*timed out*'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
        if (-not $IsWindows) {
            $clock.Restart()
            {Invoke-PasskeyExternalCommand -FilePath '/bin/bash' -Arguments @('-c','sleep 4 & exit 0') -TimeoutSeconds 1} | Should -Throw '*timed out*'
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
        }
    }
    It 'returns only stdout and exit status, with stderr suppressed' {
        $pwsh=(Get-Process -Id $PID).Path
        $result=Invoke-PasskeyExternalCommand -FilePath $pwsh -Arguments @('-NoProfile','-Command',"[Console]::Out.Write('public-output');[Console]::Error.Write('SYNTHETIC-SECRET');exit 7")
        $result.ExitCode | Should -Be 7
        $result.Output | Should -BeExactly 'public-output'
        $result | ConvertTo-Json | Should -Not -Match 'SYNTHETIC-SECRET'
    }
}
