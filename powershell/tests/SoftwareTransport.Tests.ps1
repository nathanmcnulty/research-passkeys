BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($path in @('Common/Encoding','Entra/SoftwareBrowserHeaders','Entra/SoftwareSession')) { . "$repo/powershell/src/$path.ps1" }
    . "$repo/powershell/src/Entra/LoginRequest.ps1"
    function New-LoopbackResponseFixture {
        param([int]$Status, [switch]$Follow)
        $portReservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $portReservation.Start(); $port = $portReservation.LocalEndpoint.Port; $portReservation.Stop()
        $state = [hashtable]::Synchronized(@{ Ready=[Threading.ManualResetEventSlim]::new($false); Requests=0; Listener=$null; Methods=@(); BodyLengths=@() })
        $worker = [PowerShell]::Create()
        $null = $worker.AddScript({
            param($Port, $State, $Status, $Follow)
            $listener = [Net.HttpListener]::new()
            $listener.Prefixes.Add("http://127.0.0.1:$Port/")
            $State.Listener = $listener
            try {
                $listener.Start(); $State.Ready.Set()
                $request = $listener.GetContext(); $State.Requests++
                $State.Methods += $request.Request.HttpMethod
                $reader = [IO.StreamReader]::new($request.Request.InputStream, [Text.Encoding]::UTF8, $true, 1024, $true)
                $State.BodyLengths += $reader.ReadToEnd().Length; $reader.Dispose()
                $request.Response.StatusCode = $Status
                $request.Response.Headers.Add('Location', '/must-not-follow')
                $request.Response.Headers.Add('Set-Cookie', 'SYNTHETIC-COOKIE=fixture; Path=/')
                $bytes = [Text.Encoding]::UTF8.GetBytes('SYNTHETIC-RESPONSE')
                $request.Response.ContentLength64 = $bytes.Length
                $request.Response.KeepAlive = $false
                $request.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $request.Response.Close()
                if ($Follow) {
                    $request = $listener.GetContext(); $State.Requests++
                    $State.Methods += $request.Request.HttpMethod
                    $reader = [IO.StreamReader]::new($request.Request.InputStream, [Text.Encoding]::UTF8, $true, 1024, $true)
                    $State.BodyLengths += $reader.ReadToEnd().Length; $reader.Dispose()
                    $request.Response.StatusCode = 200
                    $request.Response.ContentLength64 = $bytes.Length
                    $request.Response.KeepAlive = $false
                    $request.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                    $request.Response.Close()
                }
            } finally { $listener.Close() }
        }).AddArgument($port).AddArgument($state).AddArgument($Status).AddArgument([bool]$Follow)
        $handle = $worker.BeginInvoke()
        if (-not $state.Ready.Wait(5000)) { $worker.Dispose(); throw 'Loopback fixture did not start.' }
        return @{ Uri="http://127.0.0.1:$port/start"; State=$state; Worker=$worker; Handle=$handle }
    }
    function Close-LoopbackResponseFixture {
        param($Fixture)
        $Fixture.State.Listener.Close()
        try { $null = $Fixture.Worker.EndInvoke($Fixture.Handle) } catch { }
        $Fixture.Worker.Dispose(); $Fixture.State.Ready.Dispose()
    }
}
Describe 'Real PowerShell login redirects do not retain or forward the assertion' {
    BeforeEach {
        Mock Assert-EntraLoginUri {
            $parsed=[uri]$Uri
            if ($parsed.Host -ne '127.0.0.1' -or $parsed.Scheme -ne 'http') { throw 'Fixture refuses non-loopback traffic.' }
            $parsed
        }
    }
    It 'follows HTTP <Status> as GET after an actual POST redirect' -ForEach @(@{Status=301},@{Status=302},@{Status=303}) {
        $fixture=New-LoopbackResponseFixture -Status $Status -Follow
        $session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()
        try {
            $response=Invoke-EntraLoginWebRequest -Context @{Session=$session} -Uri $fixture.Uri -Method POST -Body 'SYNTHETIC-ASSERTION'
            [int]$response.StatusCode | Should -Be 200
            $fixture.State.Methods -join ',' | Should -Be 'POST,GET'
            $fixture.State.BodyLengths[1] | Should -Be 0
            $session.Cookies.GetCookies([uri]$fixture.Uri)['SYNTHETIC-COOKIE'].Value | Should -Be fixture
            @($Error | Where-Object FullyQualifiedErrorId -Like 'MaximumRedirectExceeded,*').Count | Should -Be 0
        } finally {Close-LoopbackResponseFixture $fixture}
    }
    It 'refuses HTTP <Status> before resubmitting an assertion' -ForEach @(@{Status=307},@{Status=308}) {
        $fixture=New-LoopbackResponseFixture -Status $Status
        try {
            {Invoke-EntraLoginWebRequest -Context @{Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()} -Uri $fixture.Uri -Method POST -Body 'SYNTHETIC-ASSERTION'} | Should -Throw '*assertion-preserving*'
            $fixture.State.Requests | Should -Be 1
        } finally {Close-LoopbackResponseFixture $fixture}
    }
}
Describe 'Real PowerShell no-redirect transport on credential-free loopback HTTP' {
    BeforeEach {
        # Pester's aggregate run can fill PowerShell's bounded error history.
        # Isolate this preservation contract, then restore the caller's history after each case.
        $callerErrors = @($Error)
        $Error.Clear()
        # Test-only substitution. Production continues to require its three Microsoft HTTPS hosts.
        Mock Assert-EntraRegistrationUri {
            $parsed = [uri]$Uri
            if ($parsed.Host -ne '127.0.0.1' -or $parsed.Scheme -ne 'http') { throw 'Fixture refuses non-loopback traffic.' }
            return $parsed
        }
    }
    AfterEach {
        $Error.Clear()
        foreach ($record in $callerErrors) { $null = $Error.Add($record) }
    }
    It 'returns real HTTP <Status> without following it or retaining the expected request error' -ForEach @(
        @{ Status=301 }, @{ Status=302 }, @{ Status=303 }, @{ Status=307 }, @{ Status=308 }
    ) {
        $fixture = New-LoopbackResponseFixture -Status $Status
        $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $prior = [Management.Automation.ErrorRecord]::new([Exception]::new('existing caller error'), 'ExistingFixtureError', [Management.Automation.ErrorCategory]::NotSpecified, $null)
        $Error.Insert(0, $prior); $errorCount = $Error.Count
        try {
            $ErrorActionPreference = 'Stop'
            $response = Invoke-EntraRegistrationWebRequest -Uri $fixture.Uri -WebSession $session -Method POST -Body 'SYNTHETIC-TAP'
            [int]$response.StatusCode | Should -Be $Status
            $response.Headers.Location | Should -Be '/must-not-follow'
            $fixture.State.Requests | Should -Be 1
            $session.Cookies.GetCookies([uri]$fixture.Uri)['SYNTHETIC-COOKIE'].Value | Should -Be fixture
            $Error.Count | Should -Be $errorCount
            [object]::ReferenceEquals($Error[0], $prior) | Should -BeTrue
        } finally { $Error.Remove($prior); Close-LoopbackResponseFixture $fixture }
    }
    It 'returns an actual service HTTP error for safe status classification' {
        $fixture = New-LoopbackResponseFixture -Status 503
        try {
            $ErrorActionPreference = 'Stop'
            $response = Invoke-EntraRegistrationWebRequest -Uri $fixture.Uri
            [int]$response.StatusCode | Should -Be 503
            $fixture.State.Requests | Should -Be 1
        } finally { Close-LoopbackResponseFixture $fixture }
    }
    It 'still fails a real connection error with fixed safe text' {
        $closed = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $closed.Start(); $port = $closed.LocalEndpoint.Port; $closed.Stop()
        $ErrorActionPreference = 'Stop'
        { Invoke-EntraRegistrationWebRequest -Uri "http://127.0.0.1:$port/start" -Method POST -Body 'SYNTHETIC-TAP' } | Should -Throw 'Registration transport failed; sensitive details suppressed.'
    }
}
