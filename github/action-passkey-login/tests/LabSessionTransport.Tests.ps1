# Offline native-transport tests. Load only Send-LabProbeRequest, never the
# production factory. A sealed, in-process fake handler has no network path.
# Add-Type and all candidate function execution require prior source approval.
BeforeAll {
    $source = Get-Content (Join-Path $PSScriptRoot '../.github/validation/LabSessionProbe.ps1') -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'Transport source must parse before offline tests load.' }
    $definitions = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Send-LabProbeRequest' })
    if ($definitions.Count -ne 1) { throw 'Expected one native transport declaration.' }
    $script:transportSource = $definitions[0].Extent.Text
    if ($script:transportSource -notmatch 'New-LabProbeHttpHandler' -or
        $script:transportSource -match '(?i)HttpClientHandler|SocketsHttpHandler|HttpWebRequest|WebClient|TcpClient|Invoke-RestMethod|Invoke-WebRequest|Start-Process|Invoke-Expression') {
        throw 'Offline transport tests require the replaceable handler factory and no alternate network path.'
    }
    . ([scriptblock]::Create($script:transportSource))
    function New-LabProbeHttpHandler { throw 'A real HTTP handler is forbidden in offline transport tests.' }
    if ($null -eq ('LabProbeOfflineFixtures.ProbeHttpHandler' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'fixtures/LabProbeHttpFixture.cs') -ErrorAction Stop
    }
    $script:transportSafeError = 'Session probe transport failed; sensitive response suppressed.'
    $script:transportUri = 'https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token'
    function New-TransportFixture {
        param([byte[]]$Bytes = [Text.Encoding]::UTF8.GetBytes('{"synthetic":true}'))
        [LabProbeOfflineFixtures.ProbeHttpHandler]::new($Bytes)
    }
    function Assert-TransportDisposed {
        $script:transportFixture.WasDisposed | Should -BeTrue
        $script:transportFixture.Content.WasDisposed | Should -BeTrue
        $script:transportFixture.Stream.WasDisposed | Should -BeTrue
    }
}

Describe 'Production HTTP request and bounded response code with no network' {
    BeforeEach {
        $script:transportFixture = New-TransportFixture
        Mock New-LabProbeHttpHandler { return $script:transportFixture }
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline transport tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline transport tests.' }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        # Also clean up the fixture-owned, unused response when validation or
        # header construction rejected the request before SendAsync returned.
        $script:transportFixture.Response.Dispose()
        $script:transportFixture.Dispose()
    }

    It 'preserves status, exact UTF-8 body and media type without charset' {
        $body = '{"synthetic":"café ☃"}'
        $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes($body))
        $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Created
        $script:transportFixture.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/json; charset=utf-8')
        $result = Send-LabProbeRequest $script:transportUri
        $result.Status | Should -Be 201
        $result.Status.GetType().FullName | Should -BeExactly 'System.Int32'
        $result.ContentType | Should -BeExactly 'application/json'
        $result.Body | Should -BeExactly $body
        @($result.Locations).Count | Should -Be 0
        $script:transportFixture.SendCalls | Should -Be 1
        $script:transportFixture.RequestMethod | Should -BeExactly 'GET'
        $script:transportFixture.RequestUri.AbsoluteUri | Should -BeExactly $script:transportUri
        $script:transportFixture.RequestHeaders.Count | Should -Be 0
        $script:transportFixture.RequestContent | Should -BeNullOrEmpty
        $script:transportFixture.SendTokenCanBeCanceled | Should -BeTrue
        $script:transportFixture.Content.StreamCreationCanBeCanceled | Should -BeTrue
        $script:transportFixture.Stream.LastReadCanBeCanceled | Should -BeTrue
        $script:transportFixture.Stream.LastReadToken.Equals($script:transportFixture.Content.StreamCreationToken) | Should -BeTrue
        Assert-TransportDisposed
    }
    It 'constructs a form POST and copies only explicit request headers' {
        $body = 'grant_type=authorization_code&code=synthetic-code&scope=openid%20profile'
        $null = Send-LabProbeRequest $script:transportUri -Method POST -Headers @{ 'X-Synthetic-Only' = 'fixture-header' } -Body $body
        $script:transportFixture.RequestMethod | Should -BeExactly 'POST'
        $script:transportFixture.RequestBody | Should -BeExactly $body
        $script:transportFixture.RequestHeaders.Count | Should -Be 1
        $script:transportFixture.RequestHeaders['X-Synthetic-Only'] | Should -BeExactly 'fixture-header'
        $script:transportFixture.RequestContentHeaders['Content-Type'] | Should -BeExactly 'application/x-www-form-urlencoded; charset=utf-8'
        Assert-TransportDisposed
        { $script:transportFixture.RequestContent.ReadAsStringAsync().GetAwaiter().GetResult() } | Should -Throw
    }
    It 'returns a redirect as data without following Location' {
        $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Found
        [void]$script:transportFixture.Response.Headers.TryAddWithoutValidation('Location', 'https://example.invalid/synthetic-callback')
        $result = Send-LabProbeRequest $script:transportUri -Headers @{ Cookie = 'ESTSAUTH=synthetic-cookie' }
        $result.Status | Should -Be 302
        @($result.Locations).Count | Should -Be 1
        $result.Locations[0] | Should -BeExactly 'https://example.invalid/synthetic-callback'
        $script:transportFixture.SendCalls | Should -Be 1
        $script:transportFixture.RequestHeaders.Cookie | Should -BeExactly 'ESTSAUTH=synthetic-cookie'
        Assert-TransportDisposed
    }
    It 'preserves multiple Location values so the protocol layer can reject ambiguity' {
        $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Found
        [void]$script:transportFixture.Response.Headers.TryAddWithoutValidation('Location', [string[]]@('https://example.invalid/one', 'https://example.invalid/two'))
        $result = Send-LabProbeRequest $script:transportUri
        @($result.Locations).Count | Should -Be 2
        $result.Locations[0] | Should -BeExactly 'https://example.invalid/one'
        $result.Locations[1] | Should -BeExactly 'https://example.invalid/two'
        $script:transportFixture.SendCalls | Should -Be 1
        Assert-TransportDisposed
    }
    It 'returns an absent media type as empty rather than silently assuming JSON' {
        $script:transportFixture.Content.Headers.ContentType = $null
        $result = Send-LabProbeRequest $script:transportUri
        $result.ContentType | Should -BeNullOrEmpty
        Assert-TransportDisposed
    }
    It 'returns non-success HTTP status as data for protocol validation' {
        $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Unauthorized
        $result = Send-LabProbeRequest $script:transportUri
        $result.Status | Should -Be 401
        $script:transportFixture.SendCalls | Should -Be 1
        Assert-TransportDisposed
    }
    It 'permits only the pinned HTTPS hosts before creating any handler: <_>' -ForEach @(
        'https://example.invalid/', 'http://login.microsoftonline.com/',
        'https://login.microsoftonline.com:444/', 'https://user@login.microsoftonline.com/',
        'https://login.microsoftonline.com/#fragment', 'https://login.microsoftonline.com.example.invalid/',
        'https://graph.microsoft.com.example.invalid/', 'file:///tmp/synthetic-only'
    ) {
        { Send-LabProbeRequest $_ } | Should -Throw '*Untrusted probe destination*'
        Should -Invoke New-LabProbeHttpHandler -Times 0 -Exactly
        $script:transportFixture.SendCalls | Should -Be 0
    }
    It 'allows the exact UserInfo host and sends only the explicitly supplied bearer' {
        $null = Send-LabProbeRequest 'https://graph.microsoft.com/oidc/userinfo' -Headers @{ Authorization = 'Bearer synthetic-opaque-token' }
        $script:transportFixture.RequestUri.AbsoluteUri | Should -BeExactly 'https://graph.microsoft.com/oidc/userinfo'
        $script:transportFixture.RequestHeaders.Count | Should -Be 1
        $script:transportFixture.RequestHeaders.Authorization | Should -BeExactly 'Bearer synthetic-opaque-token'
        Assert-TransportDisposed
    }

    It 'rejects an advertised response larger than 64 KiB before reading any body' {
        $script:transportFixture.Content.Headers.ContentLength = 65537
        { Send-LabProbeRequest $script:transportUri } | Should -Throw $script:transportSafeError
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        Assert-TransportDisposed
    }
    It 'accepts exactly 64 KiB streamed without Content-Length' {
        $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65536))
        $script:transportFixture.Content.Headers.ContentLength | Should -BeNullOrEmpty
        $result = Send-LabProbeRequest $script:transportUri
        $result.Body.Length | Should -Be 65536
        $script:transportFixture.Stream.BytesRead | Should -Be 65536
        $script:transportFixture.Stream.ReadCalls | Should -Be 17
        $script:transportFixture.Stream.LastReadToken.Equals($script:transportFixture.Content.StreamCreationToken) | Should -BeTrue
        Assert-TransportDisposed
    }
    It 'rejects a streamed body exceeding 64 KiB even with <LengthDescription>' -ForEach @(
        @{ LengthDescription = 'no Content-Length'; AdvertisedLength = $null },
        @{ LengthDescription = 'a misleading small Content-Length'; AdvertisedLength = [long]1 }
    ) {
        $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65537))
        if ($null -ne $AdvertisedLength) { $script:transportFixture.Content.Headers.ContentLength = $AdvertisedLength }
        else { $script:transportFixture.Content.Headers.ContentLength | Should -BeNullOrEmpty }
        { Send-LabProbeRequest $script:transportUri } | Should -Throw $script:transportSafeError
        $script:transportFixture.Stream.BytesRead | Should -Be 65537
        $script:transportFixture.Stream.ReadCalls | Should -Be 17
        Assert-TransportDisposed
    }
    It 'rejects malformed or truncated UTF-8 rather than replacing invalid bytes: <Case>' -ForEach @(
        @{ Case = 'invalid continuation'; Bytes = [byte[]]@(0xC3, 0x28) },
        @{ Case = 'truncated sequence'; Bytes = [byte[]]@(0xF0, 0x9F) },
        @{ Case = 'invalid leading byte'; Bytes = [byte[]]@(0xFF) }
    ) {
        $script:transportFixture = New-TransportFixture $Bytes
        { Send-LabProbeRequest $script:transportUri } | Should -Throw $script:transportSafeError
        Assert-TransportDisposed
    }
    It 'suppresses body-read failures and disposes the obtained response and stream' {
        $script:transportFixture.Stream.ThrowOnRead = $true
        { Send-LabProbeRequest $script:transportUri } | Should -Throw $script:transportSafeError
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
        Assert-TransportDisposed
    }
    It 'passes the shared deadline token to stream creation and safely handles synthetic cancellation there' {
        $script:transportFixture.Content.CancelStreamCreation = $true
        $caught = $null
        try { Send-LabProbeRequest $script:transportUri } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:transportSafeError
        $caught.ToString() | Should -Not -Match 'fixture-sensitive-stream-creation'
        $script:transportFixture.Content.StreamCreationCanBeCanceled | Should -BeTrue
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        Assert-TransportDisposed
    }
    It 'declares one 30-second body deadline shared by stream creation and every read' {
        ([regex]::Matches($script:transportSource, '\[Threading\.CancellationTokenSource\]::new\(')).Count | Should -Be 1
        $script:transportSource | Should -Match 'CancellationTokenSource\]::new\(\[TimeSpan\]::FromSeconds\(30\)\)'
        $script:transportSource | Should -Match 'ReadAsStreamAsync\(\$cancel\.Token\)'
        $script:transportSource | Should -Match 'ReadAsync\(\$bytes,\s*0,\s*\$bytes\.Length,\s*\$cancel\.Token\)'
        $script:transportSource | Should -Match '\$cancel\.Dispose\(\)'
        $script:transportSource | Should -Match '\$client\.Timeout\s*=\s*\[TimeSpan\]::FromSeconds\(30\)'
    }
    It 'suppresses handler failures and disposes the request body and handler: <_>' -ForEach @('ThrowOnSend', 'CancelOnSend') {
        $script:transportFixture.$_ = $true
        $received = [Collections.Generic.List[object]]::new()
        $caught = $null
        try {
            Send-LabProbeRequest $script:transportUri -Method POST -Body 'code=synthetic-sensitive-code' *>&1 | ForEach-Object { $received.Add($_) }
        } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:transportSafeError
        $caught.ToString() | Should -Not -Match 'fixture-sensitive|synthetic-sensitive-code'
        $received.Count | Should -Be 0
        $script:transportFixture.SendCalls | Should -Be 1
        $script:transportFixture.WasDisposed | Should -BeTrue
        { $script:transportFixture.RequestContent.ReadAsStringAsync().GetAwaiter().GetResult() } | Should -Throw
        # SendAsync did not return a response, so its unused fixture-owned
        # response is cleaned up by AfterEach, not claimed as production-owned.
    }
    It 'suppresses invalid request-header details before invoking the handler' {
        $caught = $null
        try { Send-LabProbeRequest $script:transportUri -Headers @{ Authorization = "Bearer synthetic-secret`r`nInjected: value" } } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:transportSafeError
        $caught.ToString() | Should -Not -Match 'synthetic-secret|Injected'
        $script:transportFixture.SendCalls | Should -Be 0
        $script:transportFixture.WasDisposed | Should -BeTrue
    }
    It 'enforces its real 30-second read deadline against a non-network blocked stream' -Tag 'SlowTimeout' {
        $script:transportFixture.Stream.WaitForCancellation = $true
        $watch = [Diagnostics.Stopwatch]::StartNew()
        { Send-LabProbeRequest $script:transportUri } | Should -Throw $script:transportSafeError
        $watch.Stop()
        $script:transportFixture.Stream.LastReadCanBeCanceled | Should -BeTrue
        $script:transportFixture.Stream.CancellationObserved | Should -BeTrue
        $script:transportFixture.Stream.WatchdogElapsed | Should -BeFalse
        $watch.Elapsed.TotalSeconds | Should -BeGreaterOrEqual 25
        $watch.Elapsed.TotalSeconds | Should -BeLessThan 45
        Assert-TransportDisposed
        # This establishes production body-read cancellation only. It does not
        # prove a real TLS handshake, proxy behavior or socket-connect timeout.
    }
}
