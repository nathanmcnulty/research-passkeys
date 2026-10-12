BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($path in @('Common/Encoding','Entra/SoftwareBrowserHeaders','Entra/SoftwareSession')) { . "$repo/powershell/src/$path.ps1" }
    function New-LoopbackResponseFixture {
        param([int]$Status)
        $portReservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $portReservation.Start(); $port = $portReservation.LocalEndpoint.Port; $portReservation.Stop()
        $state = [hashtable]::Synchronized(@{ Ready=[Threading.ManualResetEventSlim]::new($false); Requests=0; Listener=$null })
        $worker = [PowerShell]::Create()
        $null = $worker.AddScript({
            param($Port, $State, $Status)
            $listener = [Net.HttpListener]::new()
            $listener.Prefixes.Add("http://127.0.0.1:$Port/")
            $State.Listener = $listener
            try {
                $listener.Start(); $State.Ready.Set()
                $request = $listener.GetContext(); $State.Requests++
                $request.Response.StatusCode = $Status
                $request.Response.Headers.Add('Location', '/must-not-follow')
                $request.Response.Headers.Add('Set-Cookie', 'SYNTHETIC-COOKIE=fixture; Path=/')
                $bytes = [Text.Encoding]::UTF8.GetBytes('SYNTHETIC-RESPONSE')
                $request.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $request.Response.Close()
            } finally { $listener.Close() }
        }).AddArgument($port).AddArgument($state).AddArgument($Status)
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
Describe 'Real PowerShell no-redirect transport on credential-free loopback HTTP' {
    BeforeEach {
        # Test-only substitution. Production continues to require its three Microsoft HTTPS hosts.
        Mock Assert-EntraRegistrationUri {
            $parsed = [uri]$Uri
            if ($parsed.Host -ne '127.0.0.1' -or $parsed.Scheme -ne 'http') { throw 'Fixture refuses non-loopback traffic.' }
            return $parsed
        }
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
