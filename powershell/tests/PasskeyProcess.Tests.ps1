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
        @($info.ArgumentList)[0..2] | Should -Be @('/d','/s','/c')
        $info.ArgumentList[3] | Should -BeExactly '""C:\Program Files\Azure CLI\az.cmd" "account" "get-access-token" "--resource" "https://vault.azure.net" "--output" "json""'
        foreach ($argument in @('x&calc','x|calc','%TOKEN%','!TOKEN!','x"y','x^y',"x`ny")) {
            {New-PasskeyExternalStartInfo -FilePath 'C:\Azure\az.cmd' -Arguments @($argument) -Windows:$true} | Should -Throw '*Unsafe*'
        }
        {New-PasskeyExternalStartInfo -FilePath 'C:\Azure\other.cmd' -Arguments @('account') -Windows:$true} | Should -Throw '*Unsupported*'
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
