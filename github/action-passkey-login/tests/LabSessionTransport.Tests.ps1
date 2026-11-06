# Offline native-transport tests. Load native transport and pure protocol
# functions, never the production handler factory. Every HTTP boundary uses a
# sealed, in-process fake handler with no network path.
# Add-Type and all candidate function execution require prior source approval.
BeforeAll {
    $source = Get-Content (Join-Path $PSScriptRoot '../.github/validation/LabSessionProbe.ps1') -Raw
    $script:transportProbeSource = $source
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
    $allDefinitions = @($ast.EndBlock.Statements)
    if ($ast.BeginBlock -or $ast.ProcessBlock -or $ast.ParamBlock -or
        @($allDefinitions | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -ne 0) {
        throw 'Offline transport fixture permits only top-level function declarations.'
    }
    $factory = @($allDefinitions | Where-Object Name -CEQ 'New-LabProbeHttpHandler')
    if ($factory.Count -ne 1) { throw 'Expected one excluded native handler factory.' }
    $script:transportFactorySource = $factory[0].Extent.Text
    foreach ($definition in $allDefinitions) {
        if ($definition.Name -cin @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) { continue }
        if ($definition.Extent.Text -match '(?i)HttpClient|HttpWebRequest|WebClient|TcpClient|Socket|SendAsync|DownloadString|Start-Process|Invoke-Expression') {
            throw 'Network-capable code outside native transport is forbidden in the offline harness.'
        }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function New-LabProbeHttpHandler {
        param([hashtable]$Diagnostic)
        throw 'A real HTTP handler is forbidden in offline transport tests.'
    }
    $baselinePath = Join-Path $PSScriptRoot 'fixtures/LabSessionProbe.Baseline.ps1'
    if ((Get-FileHash $baselinePath -Algorithm SHA256).Hash -cne '9A42B6785D3D4E70108B0D8D4CB88C106123ADB4994B564A0B2AB3F7A6D639CC') {
        throw 'Native differential baseline must retain its independently pinned bytes.'
    }
    $baselineSource = Get-Content $baselinePath -Raw
    $baselineTokens = $null; $baselineErrors = $null
    $baselineAst = [Management.Automation.Language.Parser]::ParseInput($baselineSource, [ref]$baselineTokens, [ref]$baselineErrors)
    if ($baselineErrors.Count -ne 0) { throw 'Pinned native transport baseline must parse before extraction.' }
    $baselineDefinitions = @($baselineAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Send-LabProbeRequest' })
    if ($baselineDefinitions.Count -ne 1) { throw 'Expected one pinned baseline transport declaration.' }
    $baselineTransport = $baselineDefinitions[0].Extent.Text
    if ($baselineTransport -notmatch 'New-LabProbeHttpHandler' -or
        $baselineTransport -match '(?i)HttpClientHandler|SocketsHttpHandler|HttpWebRequest|WebClient|TcpClient|Invoke-RestMethod|Invoke-WebRequest|Start-Process|Invoke-Expression') {
        throw 'Pinned baseline transport must retain only the replaceable fake-handler boundary.'
    }
    # Extract only this declaration, never either production handler factory.
    $baselineTransport = $baselineTransport.Replace('function Send-LabProbeRequest {', 'function Send-BaselineLabProbeRequest {').Replace('New-LabProbeHttpHandler', 'New-BaselineLabProbeHttpHandler')
    . ([scriptblock]::Create($baselineTransport))
    function New-BaselineLabProbeHttpHandler { throw 'A real baseline HTTP handler is forbidden in offline transport tests.' }
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
    function Assert-TransportDiagnostic {
        param([hashtable]$Diagnostic, [string]$Predicate)
        $Diagnostic.Code | Should -BeExactly 'TransportFailure'
        $Diagnostic.Predicate | Should -BeExactly $Predicate
    }
    function Assert-TransportDiagnosticReset {
        param([hashtable]$Diagnostic)
        $Diagnostic.Code | Should -BeExactly 'UnexpectedFailure'
        $Diagnostic.Predicate | Should -BeExactly 'UnexpectedFailure'
    }
    function Assert-TransportFailure {
        param([string]$Predicate, [scriptblock]$Action, [switch]$OriginalRawError)
        $diagnostic = @{}
        $received = [Collections.Generic.List[object]]::new()
        $caught = $null
        $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; $InformationPreference = 'Continue'; $WarningPreference = 'Continue'
        try { & $Action $diagnostic *>&1 | ForEach-Object { $received.Add($_) } } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        Assert-TransportDiagnostic $diagnostic $Predicate
        if (-not $OriginalRawError) {
            $caught.Exception.Message | Should -BeExactly $script:transportSafeError
            $caught.Exception.InnerException | Should -BeNullOrEmpty
            $received.Count | Should -Be 0
            $rendered = @($caught.ToString(), $caught.Exception.ToString(), ($caught | Out-String),
                ($caught | Format-List * -Force | Out-String), [string]$caught.TargetObject, [string]$caught.ErrorDetails) -join "`n"
            $rendered | Should -Not -Match 'fixture-sensitive|synthetic-sensitive|diagnostic-secret'
        } else {
            $caught.Exception.Message | Should -Not -BeExactly $script:transportSafeError
        }
        # Setup and Dispose exceptions historically escape this low-level
        # helper. Assert their sanitization at Invoke-LabSessionProbe instead;
        # a diagnostic-only patch must not silently change that behavior.
    }
    function Assert-PublicTransportFailure {
        param([string]$Predicate)
        $received = [Collections.Generic.List[object]]::new()
        $caught = $null
        $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; $InformationPreference = 'Continue'; $WarningPreference = 'Continue'
        try { Invoke-LabSessionProbe @script:transportProbeArguments *>&1 | ForEach-Object { $received.Add($_) } } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly "Server-backed session probe failed; no live acceptance. Sensitive details suppressed. Phase=DiscoveryRequest; Code=TransportFailure; Predicate=$Predicate."
        $caught.Exception.InnerException | Should -BeNullOrEmpty
        $received.Count | Should -Be 0
        $rendered = @($caught.ToString(), $caught.Exception.ToString(), ($caught | Out-String),
            ($caught | Format-List * -Force | Out-String), [string]$caught.TargetObject, [string]$caught.ErrorDetails) -join "`n"
        $rendered | Should -Not -Match 'fixture-sensitive|synthetic-cookie|synthetic-sensitive|diagnostic-secret|fixture@example|11111111-1111|22222222-2222'
    }
    function Reset-TransportFixtureFaults {
        # This is test-owned teardown, not a production retry. A failed Dispose
        # is allowed to stop production cleanup in its original position.
        $script:transportFixture.Stream.ThrowOnDispose = $false
        $script:transportFixture.Content.ThrowOnDispose = $false
        $script:transportFixture.ThrowOnDispose = $false
        if ($null -ne $script:transportFixture.InjectedRequestContent) {
            $script:transportFixture.InjectedRequestContent.ThrowOnDispose = $false
            $script:transportFixture.InjectedRequestContent.Dispose()
        }
        if ($null -ne $script:transportFixture.Request) { $script:transportFixture.Request.Dispose() }
        $script:transportFixture.Response.Dispose()
        $script:transportFixture.Content.Dispose()
        $script:transportFixture.Stream.Dispose()
        $script:transportFixture.Dispose()
    }
    function ConvertTo-TransportSnapshotValue {
        param($Value)
        if ($null -eq $Value) { return [ordered]@{ Type = $null; Value = $null } }
        $type = $Value.GetType().FullName
        if ($Value -is [Collections.IDictionary]) {
            $entries = @(
                foreach ($key in @($Value.Keys | Sort-Object)) {
                    [ordered]@{ Key = [string]$key; Value = (ConvertTo-TransportSnapshotValue $Value[$key]) }
                }
            )
            return [ordered]@{ Type = $type; Entries = $entries }
        }
        if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @(foreach ($item in $Value) { ConvertTo-TransportSnapshotValue $item })
            return [ordered]@{ Type = $type; Items = $items }
        }
        return [ordered]@{ Type = $type; Value = [string]$Value }
    }
    function Get-TransportDifferentialSnapshot {
        param([string]$Command, [string]$Case)
        $script:transportFixture = New-TransportFixture
        $script:transportDifferentialFactory = ''
        $arguments = @{ Uri = $script:transportUri }
        switch ($Case) {
            'Post' { $arguments.Method = 'POST'; $arguments.Body = 'code=synthetic-sensitive-code'; $arguments.Headers = @{ 'X-Synthetic' = 'fixture-only' } }
            'Redirect' { $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Found; [void]$script:transportFixture.Response.Headers.TryAddWithoutValidation('Location', 'https://example.invalid/synthetic-callback') }
            'UriConstruction' { $arguments.Uri = 'https://[fixture-sensitive-malformed' }
            'Scheme' { $arguments.Uri = 'http://login.microsoftonline.com/' }
            'Port' { $arguments.Uri = 'https://login.microsoftonline.com:444/' }
            'UserInfo' { $arguments.Uri = 'https://user@login.microsoftonline.com/' }
            'Fragment' { $arguments.Uri = 'https://login.microsoftonline.com/#fixture-sensitive' }
            'Host' { $arguments.Uri = 'https://example.invalid/' }
            'LoginHostSuffix' { $arguments.Uri = 'https://login.microsoftonline.com.example.invalid/' }
            'GraphHostSuffix' { $arguments.Uri = 'https://graph.microsoft.com.example.invalid/' }
            'FileUri' { $arguments.Uri = 'file:///tmp/synthetic-only' }
            'Headers' { $arguments.Headers = @{ Authorization = "Bearer synthetic-sensitive`r`nInjected: value" } }
            'Method' { $arguments.Method = "GET`r`nfixture-sensitive-method" }
            'FactoryThrow' { $script:transportDifferentialFactory = 'Throw' }
            'FactoryNull' { $script:transportDifferentialFactory = 'Null' }
            'Send' { $script:transportFixture.ThrowOnSend = $true }
            'SendCancel' { $script:transportFixture.CancelOnSend = $true }
            'Open' { $script:transportFixture.Content.ThrowOnStreamCreation = $true }
            'OpenCancel' { $script:transportFixture.Content.CancelStreamCreation = $true }
            'Read' { $script:transportFixture.Stream.ThrowOnRead = $true }
            'ReadCancel' { $script:transportFixture.Stream.CancelOnRead = $true }
            'AdvertisedLimit' { $script:transportFixture.Content.Headers.ContentLength = 65537 }
            'ExactLimit' { $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65536)); $script:transportFixture.Content.Headers.ContentLength = 65536 }
            'StreamedLimit' { $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65537)) }
            'MisleadingLimit' { $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65537)); $script:transportFixture.Content.Headers.ContentLength = 1 }
            'BufferWrite' { $script:transportFixture.Stream.ReportedReadCount = -1 }
            'Utf8' { $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF)) }
            'StreamDispose' { $script:transportFixture.Stream.ThrowOnDispose = $true }
            'ResponseDispose' { $script:transportFixture.Content.ThrowOnDispose = $true }
            'RequestDispose' { $script:transportFixture.InjectRequestContent = $true; $script:transportFixture.ThrowOnRequestContentDispose = $true }
            'ClientDispose' { $script:transportFixture.ThrowOnDispose = $true }
            'ReadThenStreamDispose' { $script:transportFixture.Stream.ThrowOnRead = $true; $script:transportFixture.Stream.ThrowOnDispose = $true }
            'ReadThenResponseDispose' { $script:transportFixture.Stream.ThrowOnRead = $true; $script:transportFixture.Content.ThrowOnDispose = $true }
            'ReadThenRequestDispose' { $script:transportFixture.Stream.ThrowOnRead = $true; $script:transportFixture.InjectRequestContent = $true; $script:transportFixture.ThrowOnRequestContentDispose = $true }
            'ReadThenClientDispose' { $script:transportFixture.Stream.ThrowOnRead = $true; $script:transportFixture.ThrowOnDispose = $true }
            'Utf8ThenResponseDispose' { $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF)); $script:transportFixture.Content.ThrowOnDispose = $true }
            'SendThenClientDispose' { $script:transportFixture.ThrowOnSend = $true; $script:transportFixture.ThrowOnDispose = $true }
        }
        $received = [Collections.Generic.List[object]]::new()
        $caught = $null
        $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; $InformationPreference = 'Continue'; $WarningPreference = 'Continue'
        try {
            # Do not assign the helper result to $null: baseline Dispose-only
            # failures may already have emitted a partial success object.
            try { & $Command @arguments *>&1 | ForEach-Object { $received.Add($_) } } catch { $caught = $_ }
            $snapshot = [ordered]@{
                Accepted = ($null -eq $caught)
                Output = @(foreach ($item in $received) { ConvertTo-TransportSnapshotValue $item })
                ErrorType = $(if ($caught) { $caught.Exception.GetType().FullName } else { $null })
                ErrorMessage = $(if ($caught) { $caught.Exception.Message } else { $null })
                RequestUri = $(if ($script:transportFixture.RequestUri) { $script:transportFixture.RequestUri.AbsoluteUri } else { $null })
                RequestMethod = $script:transportFixture.RequestMethod
                RequestBody = $script:transportFixture.RequestBody
                RequestHeaders = (ConvertTo-TransportSnapshotValue $script:transportFixture.RequestHeaders)
                RequestContentHeaders = (ConvertTo-TransportSnapshotValue $script:transportFixture.RequestContentHeaders)
                SendCalls = $script:transportFixture.SendCalls
                ReadCalls = $script:transportFixture.Stream.ReadCalls
                BytesRead = $script:transportFixture.Stream.BytesRead
                StreamCreationCalls = $script:transportFixture.Content.StreamCreationCalls
                SendCancelable = $script:transportFixture.SendTokenCanBeCanceled
                OpenCancelable = $script:transportFixture.Content.StreamCreationCanBeCanceled
                ReadCancelable = $script:transportFixture.Stream.LastReadCanBeCanceled
                DisposalEvents = @($script:transportFixture.DisposeEvents)
                HandlerDisposed = $script:transportFixture.WasDisposed
                ResponseContentDisposed = $script:transportFixture.Content.WasDisposed
                StreamDisposed = $script:transportFixture.Stream.WasDisposed
            }
            return ($snapshot | ConvertTo-Json -Depth 20 -Compress)
        } finally { Reset-TransportFixtureFaults }
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
        Reset-TransportFixtureFaults
    }

    It 'preserves status, exact UTF-8 body and media type without charset' {
        $body = '{"synthetic":"café ☃"}'
        $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes($body))
        $script:transportFixture.Response.StatusCode = [Net.HttpStatusCode]::Created
        $script:transportFixture.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/json; charset=utf-8')
        $diagnostic = @{}
        $result = Send-LabProbeRequest $script:transportUri -Diagnostic $diagnostic
        Assert-TransportDiagnosticReset $diagnostic
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
        Assert-TransportFailure TransportAdvertisedLimit { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
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
        Assert-TransportFailure TransportStreamedLimit { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Stream.BytesRead | Should -Be 65537
        $script:transportFixture.Stream.ReadCalls | Should -Be 17
        Assert-TransportDisposed
    }
    It 'rejects malformed or truncated UTF-8 rather than replacing invalid bytes: <Case>' -ForEach @(
        @{ Case = 'invalid continuation'; Bytes = [byte[]]@(0xC3, 0x28) },
        @{ Case = 'truncated sequence'; Bytes = [byte[]]@(0xF0, 0x9F) },
        @{ Case = 'invalid leading byte'; Bytes = [byte[]]@(0xFF) },
        @{ Case = 'overlong sequence'; Bytes = [byte[]]@(0xC0, 0xAF) },
        @{ Case = 'UTF-16 surrogate'; Bytes = [byte[]]@(0xED, 0xA0, 0x80) },
        @{ Case = 'above Unicode maximum'; Bytes = [byte[]]@(0xF4, 0x90, 0x80, 0x80) }
    ) {
        $script:transportFixture = New-TransportFixture $Bytes
        Assert-TransportFailure TransportUtf8Decode { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        Assert-TransportDisposed
    }
    It 'suppresses body-read failures and disposes the obtained response and stream' {
        $script:transportFixture.Stream.ThrowOnRead = $true
        Assert-TransportFailure TransportRead { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
        Assert-TransportDisposed
    }
    It 'passes the shared deadline token to stream creation and safely handles synthetic cancellation there' {
        $script:transportFixture.Content.CancelStreamCreation = $true
        $caught = $null
        $diagnostic = @{}
        try { Send-LabProbeRequest $script:transportUri -Diagnostic $diagnostic } catch { $caught = $_ }
        Assert-TransportDiagnostic $diagnostic TransportStreamOpen
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
        $diagnostic = @{}
        $received = [Collections.Generic.List[object]]::new()
        $caught = $null
        try {
            Send-LabProbeRequest $script:transportUri -Method POST -Body 'code=synthetic-sensitive-code' -Diagnostic $diagnostic *>&1 | ForEach-Object { $received.Add($_) }
        } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:transportSafeError
        $caught.ToString() | Should -Not -Match 'fixture-sensitive|synthetic-sensitive-code'
        $received.Count | Should -Be 0
        Assert-TransportDiagnostic $diagnostic TransportSend
        $script:transportFixture.SendCalls | Should -Be 1
        $script:transportFixture.WasDisposed | Should -BeTrue
        { $script:transportFixture.RequestContent.ReadAsStringAsync().GetAwaiter().GetResult() } | Should -Throw
        # SendAsync did not return a response, so its unused fixture-owned
        # response is cleaned up by AfterEach, not claimed as production-owned.
    }
    It 'suppresses invalid request-header details before invoking the handler' {
        $caught = $null
        $diagnostic = @{}
        try { Send-LabProbeRequest $script:transportUri -Headers @{ Authorization = "Bearer synthetic-secret`r`nInjected: value" } -Diagnostic $diagnostic } catch { $caught = $_ }
        Assert-TransportDiagnostic $diagnostic TransportHeaderConstruction
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:transportSafeError
        $caught.ToString() | Should -Not -Match 'synthetic-secret|Injected'
        $script:transportFixture.SendCalls | Should -Be 0
        $script:transportFixture.WasDisposed | Should -BeTrue
    }
    It 'enforces its real 30-second read deadline against a non-network blocked stream' -Tag 'SlowTimeout' {
        $script:transportFixture.Stream.WaitForCancellation = $true
        $watch = [Diagnostics.Stopwatch]::StartNew()
        Assert-TransportFailure TransportRead { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
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

Describe 'First entered native transport predicates with exclusively fake HTTP' {
    BeforeEach {
        $script:transportFixture = New-TransportFixture
        $script:transportProbeArguments = @{
            TenantId = '11111111-1111-4111-8111-111111111111'
            ClientId = '22222222-2222-4222-8222-222222222222'
            ExpectedUpn = 'fixture@example.invalid'
            CookieName = 'ESTSAUTH'
            Cookie = 'synthetic-cookie-never-a-real-credential'
        }
        Mock New-LabProbeHttpHandler { return $script:transportFixture }
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline transport tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline transport tests.' }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Reset-TransportFixtureFaults
    }

    It 'identifies the first destination predicate before any handler: <Predicate>' -ForEach @(
        @{ Predicate = 'TransportUriConstruction'; Uri = 'https://[fixture-sensitive-malformed' },
        @{ Predicate = 'TransportScheme'; Uri = 'http://user@example.invalid:444/#fixture-sensitive' },
        @{ Predicate = 'TransportPort'; Uri = 'https://user@example.invalid:444/#fixture-sensitive' },
        @{ Predicate = 'TransportUserInfo'; Uri = 'https://user@example.invalid/#fixture-sensitive' },
        @{ Predicate = 'TransportFragment'; Uri = 'https://example.invalid/#fixture-sensitive' },
        @{ Predicate = 'TransportHost'; Uri = 'https://example.invalid/' }
    ) {
        $caseUri = $Uri
        Assert-TransportFailure $Predicate { param($Diagnostic) Send-LabProbeRequest $caseUri -Diagnostic $Diagnostic } -OriginalRawError
        Should -Invoke New-LabProbeHttpHandler -Times 0 -Exactly
        $script:transportFixture.SendCalls | Should -Be 0
        $script:transportFixture.DisposeEvents.Count | Should -Be 0
    }
    It 'keeps destination validation ahead of handler construction and its synthetic failure' {
        Mock New-LabProbeHttpHandler { throw 'fixture-sensitive-handler-creation' }
        Assert-TransportFailure TransportScheme {
            param($Diagnostic)
            Send-LabProbeRequest 'http://example.invalid:444/#fixture-sensitive' -Diagnostic $Diagnostic
        } -OriginalRawError
        Should -Invoke New-LabProbeHttpHandler -Times 0 -Exactly
    }
    It 'identifies a handler-factory throw without loading the production factory' {
        Mock New-LabProbeHttpHandler { throw 'fixture-sensitive-handler-creation' }
        Assert-TransportFailure TransportHandlerConstruction { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        Should -Invoke New-LabProbeHttpHandler -Times 1 -Exactly
        $script:transportFixture.SendCalls | Should -Be 0
        $script:transportFixture.DisposeEvents.Count | Should -Be 0
    }
    It 'identifies native HttpClient construction failure with a null fake factory result' {
        Mock New-LabProbeHttpHandler { return $null }
        Assert-TransportFailure TransportClientConstruction { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        Should -Invoke New-LabProbeHttpHandler -Times 1 -Exactly
        $script:transportFixture.SendCalls | Should -Be 0
    }
    It 'identifies invalid native method construction before a request can be sent' {
        Assert-TransportFailure TransportMethodConstruction {
            param($Diagnostic)
            Send-LabProbeRequest $script:transportUri -Method "GET`r`nfixture-sensitive-method" -Diagnostic $Diagnostic
        } -OriginalRawError
        $script:transportFixture.SendCalls | Should -Be 0
        # This setup operation is outside the original try/finally. Do not
        # claim production disposed resources it historically did not own yet.
        $script:transportFixture.WasDisposed | Should -BeFalse
    }
    It 'keeps header construction ahead of send and body/read faults' {
        $script:transportFixture.ThrowOnSend = $true
        $script:transportFixture.Stream.ThrowOnRead = $true
        Assert-TransportFailure TransportHeaderConstruction {
            param($Diagnostic)
            Send-LabProbeRequest $script:transportUri -Headers @{ Authorization = "Bearer diagnostic-secret`r`nInjected: value" } -Diagnostic $Diagnostic
        }
        $script:transportFixture.SendCalls | Should -Be 0
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        $script:transportFixture.WasDisposed | Should -BeTrue
    }
    It 'keeps send ahead of response length and stream faults' {
        $script:transportFixture.ThrowOnSend = $true
        $script:transportFixture.Content.Headers.ContentLength = 65537
        $script:transportFixture.Content.ThrowOnStreamCreation = $true
        Assert-TransportFailure TransportSend { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.SendCalls | Should -Be 1
        $script:transportFixture.Content.StreamCreationCalls | Should -Be 0
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
    }
    It 'keeps the advertised limit ahead of stream creation, reads and UTF-8 decoding' {
        $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF))
        $script:transportFixture.Content.Headers.ContentLength = 65537
        $script:transportFixture.Content.ThrowOnStreamCreation = $true
        $script:transportFixture.Stream.ThrowOnRead = $true
        Assert-TransportFailure TransportAdvertisedLimit { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Content.StreamCreationCalls | Should -Be 0
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        Assert-TransportDisposed
    }
    It 'identifies stream opening failure before any body reads' {
        $script:transportFixture.Content.ThrowOnStreamCreation = $true
        $script:transportFixture.Stream.ThrowOnRead = $true
        Assert-TransportFailure TransportStreamOpen { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Content.StreamCreationCalls | Should -Be 1
        $script:transportFixture.Content.StreamCreationCanBeCanceled | Should -BeTrue
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        Assert-TransportDisposed
    }
    It 'identifies a canceled native read without requiring a real deadline wait' {
        $script:transportFixture.Stream.CancelOnRead = $true
        Assert-TransportFailure TransportRead { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
        $script:transportFixture.Stream.LastReadToken.Equals($script:transportFixture.Content.StreamCreationToken) | Should -BeTrue
        Assert-TransportDisposed
    }
    It 'identifies native buffer write failure from an invalid fake stream count' {
        $script:transportFixture.Stream.ReportedReadCount = -1
        Assert-TransportFailure TransportBufferWrite { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
        Assert-TransportDisposed
    }
    It 'keeps the streamed limit ahead of later invalid UTF-8 decoding' {
        $bytes = [byte[]]::new(65537)
        $bytes[0] = 0xFF
        $script:transportFixture = New-TransportFixture $bytes
        Assert-TransportFailure TransportStreamedLimit { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic }
        $script:transportFixture.Stream.BytesRead | Should -Be 65537
        $script:transportFixture.Stream.ReadCalls | Should -Be 17
        Assert-TransportDisposed
    }
    It 'accepts the exact advertised and streamed byte limit with multibyte UTF-8 across read boundaries' {
        # 21,844 three-byte code points plus four ASCII bytes equals 65,536.
        # The 4,096-byte reader splits valid characters between reads.
        $body = ('☃' * 21844) + 'abcd'
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $bytes.Length | Should -Be 65536
        $script:transportFixture = New-TransportFixture $bytes
        $script:transportFixture.Content.Headers.ContentLength = 65536
        $diagnostic = @{}
        $result = Send-LabProbeRequest $script:transportUri -Diagnostic $diagnostic
        $result.Body | Should -BeExactly $body
        $script:transportFixture.Stream.BytesRead | Should -Be 65536
        $script:transportFixture.Stream.ReadCalls | Should -Be 17
        Assert-TransportDiagnosticReset $diagnostic
        Assert-TransportDisposed
    }
    It 'preserves empty-body transport success without inventing a JSON acceptance decision' {
        $script:transportFixture = New-TransportFixture ([byte[]]::new(0))
        $diagnostic = @{}
        $result = Send-LabProbeRequest $script:transportUri -Diagnostic $diagnostic
        $result.Body | Should -BeExactly ''
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
        Assert-TransportDiagnosticReset $diagnostic
        Assert-TransportDisposed
    }
    It 'preserves original successful disposal order including native request content ownership' {
        $script:transportFixture.InjectRequestContent = $true
        $null = Send-LabProbeRequest $script:transportUri -Diagnostic @{}
        $events = @($script:transportFixture.DisposeEvents)
        # HttpContent may dispose its owned stream more than once; all stream
        # cleanup still precedes request and handler cleanup.
        $events[0] | Should -BeExactly 'Stream'
        $events[1] | Should -BeExactly 'ResponseContent'
        $events[-2] | Should -BeExactly 'RequestContent'
        $events[-1] | Should -BeExactly 'Handler'
        $script:transportFixture.InjectedRequestContent.WasDisposed | Should -BeTrue
        Assert-TransportDisposed
    }
    It 'identifies the first throwing cleanup and does not continue later cleanup: <Predicate>' -ForEach @(
        @{ Predicate = 'TransportStreamDispose'; Fault = 'Stream'; LastEvent = 'Stream'; HandlerDisposed = $false; RequestDisposed = $false },
        @{ Predicate = 'TransportResponseDispose'; Fault = 'Content'; LastEvent = 'ResponseContent'; HandlerDisposed = $false; RequestDisposed = $false },
        @{ Predicate = 'TransportRequestDispose'; Fault = 'Request'; LastEvent = 'RequestContent'; HandlerDisposed = $false; RequestDisposed = $true },
        @{ Predicate = 'TransportClientDispose'; Fault = 'Handler'; LastEvent = 'Handler'; HandlerDisposed = $true; RequestDisposed = $true }
    ) {
        $script:transportFixture.InjectRequestContent = $true
        switch ($Fault) {
            'Stream' { $script:transportFixture.Stream.ThrowOnDispose = $true }
            'Content' { $script:transportFixture.Content.ThrowOnDispose = $true }
            'Request' { $script:transportFixture.ThrowOnRequestContentDispose = $true }
            'Handler' { $script:transportFixture.ThrowOnDispose = $true }
        }
        Assert-TransportFailure $Predicate { param($Diagnostic) $null = Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        $script:transportFixture.DisposeEvents[-1] | Should -BeExactly $LastEvent
        $script:transportFixture.WasDisposed | Should -Be $HandlerDisposed
        $script:transportFixture.InjectedRequestContent.WasDisposed | Should -Be $RequestDisposed
    }
    It 'retains the first read predicate when later cleanup also throws: <_>' -ForEach @('Stream', 'Content', 'Request', 'Handler') {
        $script:transportFixture.InjectRequestContent = $true
        $script:transportFixture.Stream.ThrowOnRead = $true
        switch ($_) {
            'Stream' { $script:transportFixture.Stream.ThrowOnDispose = $true }
            'Content' { $script:transportFixture.Content.ThrowOnDispose = $true }
            'Request' { $script:transportFixture.ThrowOnRequestContentDispose = $true }
            'Handler' { $script:transportFixture.ThrowOnDispose = $true }
        }
        Assert-TransportFailure TransportRead { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        $script:transportFixture.Stream.ReadCalls | Should -Be 1
    }
    It 'retains UTF-8 failure when response disposal subsequently throws' {
        $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF))
        $script:transportFixture.Content.ThrowOnDispose = $true
        Assert-TransportFailure TransportUtf8Decode { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        $script:transportFixture.DisposeEvents[-1] | Should -BeExactly 'ResponseContent'
        $script:transportFixture.WasDisposed | Should -BeFalse
    }
    It 'retains advertised-limit failure when only response cleanup is reachable and throws' {
        $script:transportFixture.Content.Headers.ContentLength = 65537
        $script:transportFixture.Content.ThrowOnDispose = $true
        Assert-TransportFailure TransportAdvertisedLimit { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        $script:transportFixture.Stream.ReadCalls | Should -Be 0
        ($script:transportFixture.DisposeEvents -join ',') | Should -BeExactly 'ResponseContent'
    }
    It 'retains send failure when handler cleanup also throws and no response was obtained' {
        $script:transportFixture.ThrowOnSend = $true
        $script:transportFixture.ThrowOnDispose = $true
        Assert-TransportFailure TransportSend { param($Diagnostic) Send-LabProbeRequest $script:transportUri -Diagnostic $Diagnostic } -OriginalRawError
        ($script:transportFixture.DisposeEvents -join ',') | Should -BeExactly 'Handler'
        $script:transportFixture.Content.WasDisposed | Should -BeFalse
        $script:transportFixture.Stream.WasDisposed | Should -BeFalse
    }

    It 'sanitizes native operation and cleanup exceptions at the public probe boundary: <Predicate>' -ForEach @(
        @{ Predicate = 'TransportHandlerConstruction'; Fault = 'Factory' },
        @{ Predicate = 'TransportClientConstruction'; Fault = 'Client' },
        @{ Predicate = 'TransportSend'; Fault = 'Send' },
        @{ Predicate = 'TransportSend'; Fault = 'SendCancel' },
        @{ Predicate = 'TransportAdvertisedLimit'; Fault = 'AdvertisedLimit' },
        @{ Predicate = 'TransportStreamOpen'; Fault = 'Open' },
        @{ Predicate = 'TransportStreamOpen'; Fault = 'OpenCancel' },
        @{ Predicate = 'TransportRead'; Fault = 'Read' },
        @{ Predicate = 'TransportRead'; Fault = 'ReadCancel' },
        @{ Predicate = 'TransportStreamedLimit'; Fault = 'StreamedLimit' },
        @{ Predicate = 'TransportBufferWrite'; Fault = 'Write' },
        @{ Predicate = 'TransportUtf8Decode'; Fault = 'Utf8' },
        @{ Predicate = 'TransportStreamDispose'; Fault = 'StreamDispose' },
        @{ Predicate = 'TransportResponseDispose'; Fault = 'ResponseDispose' },
        @{ Predicate = 'TransportRequestDispose'; Fault = 'RequestDispose' },
        @{ Predicate = 'TransportClientDispose'; Fault = 'ClientDispose' },
        @{ Predicate = 'TransportRead'; Fault = 'ReadThenStreamDispose' },
        @{ Predicate = 'TransportUtf8Decode'; Fault = 'Utf8ThenResponseDispose' },
        @{ Predicate = 'TransportSend'; Fault = 'SendThenClientDispose' }
    ) {
        switch ($Fault) {
            'Factory' { Mock New-LabProbeHttpHandler { throw 'fixture-sensitive-handler-creation' } }
            'Client' { Mock New-LabProbeHttpHandler { return $null } }
            'Send' { $script:transportFixture.ThrowOnSend = $true }
            'SendCancel' { $script:transportFixture.CancelOnSend = $true }
            'AdvertisedLimit' { $script:transportFixture.Content.Headers.ContentLength = 65537 }
            'Open' { $script:transportFixture.Content.ThrowOnStreamCreation = $true }
            'OpenCancel' { $script:transportFixture.Content.CancelStreamCreation = $true }
            'Read' { $script:transportFixture.Stream.ThrowOnRead = $true }
            'ReadCancel' { $script:transportFixture.Stream.CancelOnRead = $true }
            'StreamedLimit' { $script:transportFixture = New-TransportFixture ([Text.Encoding]::UTF8.GetBytes('x' * 65537)) }
            'Write' { $script:transportFixture.Stream.ReportedReadCount = -1 }
            'Utf8' { $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF)) }
            'StreamDispose' { $script:transportFixture.Stream.ThrowOnDispose = $true }
            'ResponseDispose' { $script:transportFixture.Content.ThrowOnDispose = $true }
            'RequestDispose' { $script:transportFixture.InjectRequestContent = $true; $script:transportFixture.ThrowOnRequestContentDispose = $true }
            'ClientDispose' { $script:transportFixture.ThrowOnDispose = $true }
            'ReadThenStreamDispose' { $script:transportFixture.Stream.ThrowOnRead = $true; $script:transportFixture.Stream.ThrowOnDispose = $true }
            'Utf8ThenResponseDispose' { $script:transportFixture = New-TransportFixture ([byte[]]@(0xFF)); $script:transportFixture.Content.ThrowOnDispose = $true }
            'SendThenClientDispose' { $script:transportFixture.ThrowOnSend = $true; $script:transportFixture.ThrowOnDispose = $true }
        }
        Assert-PublicTransportFailure $Predicate
        $script:transportFixture.SendCalls | Should -Be $(if ($Fault -in @('Factory', 'Client')) { 0 } else { 1 })
    }
}

Describe 'Source-only coverage for transport operations that cannot safely be fault-injected' {
    It 'lists every fixed native transport predicate in its original operation order' {
        $actual = @([regex]::Matches($script:transportSource, '\$Diagnostic\.Predicate\s*=\s*''(Transport[A-Za-z0-9]+)''') | ForEach-Object { $_.Groups[1].Value })
        $expected = @(
            'TransportUriConstruction', 'TransportScheme', 'TransportPort', 'TransportUserInfo', 'TransportFragment', 'TransportHost',
            'TransportHandlerConstruction', 'TransportClientConstruction', 'TransportTimeoutConfiguration', 'TransportMethodConstruction',
            'TransportRequestConstruction', 'TransportBufferConstruction', 'TransportHeaderConstruction', 'TransportBodyConstruction',
            'TransportSend', 'TransportAdvertisedLimit', 'TransportDeadlineConstruction', 'TransportStreamOpen', 'TransportReadBufferConstruction',
            'TransportRead', 'TransportStreamedLimit', 'TransportBufferWrite', 'TransportLocationRead', 'TransportResponseProjection',
            'TransportUtf8Decode', 'TransportStreamDispose', 'TransportResponseDispose', 'TransportDeadlineDispose', 'TransportBufferDispose',
            'TransportRequestDispose', 'TransportClientDispose'
        )
        ($actual -join ',') | Should -BeExactly ($expected -join ',')
        $script:transportSource | Should -Match '\$Diagnostic\.Code\s*=\s*''TransportFailure'''
    }
    It 'contains exactly the same 35 fixed transport IDs in every public request-phase allowlist' {
        $assigned = @([regex]::Matches(($script:transportSource + $script:transportFactorySource), '\$Diagnostic\.Predicate\s*=\s*''(Transport[A-Za-z0-9]+)''') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $assigned.Count | Should -Be 35
        foreach ($phase in @('DiscoveryRequest', 'AuthorizationRequest', 'TokenRequest', 'UserInfoRequest')) {
            $pattern = "'" + $phase + '/TransportFailure''\s*=\s*@\((?<ids>.*?)\)'
            $match = [regex]::Match($script:transportProbeSource, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)
            $match.Success | Should -BeTrue
            $allowed = @([regex]::Matches($match.Groups['ids'].Value, "'(Transport[A-Za-z0-9]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
            $allowed.Count | Should -Be 35
            ($allowed -join ',') | Should -BeExactly ($assigned -join ',')
        }
    }
    It 'assigns each rejecting guard ID only after its condition is true: <Predicate>' -ForEach @(
        @{ Predicate = 'TransportScheme'; Condition = '$target.Scheme -cne ''https''' },
        @{ Predicate = 'TransportPort'; Condition = '$target.Port -ne 443' },
        @{ Predicate = 'TransportUserInfo'; Condition = '$target.UserInfo' },
        @{ Predicate = 'TransportFragment'; Condition = '$target.Fragment' },
        @{ Predicate = 'TransportHost'; Condition = '$target.Host -cnotin @(''login.microsoftonline.com'', ''graph.microsoft.com'')' },
        @{ Predicate = 'TransportAdvertisedLimit'; Condition = '$response.Content.Headers.ContentLength -gt 65536' },
        @{ Predicate = 'TransportStreamedLimit'; Condition = '$buffer.Length + $count -gt 65536' }
    ) {
        $reset = '\$Diagnostic\.Code\s*=\s*''UnexpectedFailure'';\s*\$Diagnostic\.Predicate\s*=\s*''UnexpectedFailure'''
        $rejection = '\$Diagnostic\.Code\s*=\s*''TransportFailure'';\s*\$Diagnostic\.Predicate\s*=\s*''' + $Predicate + ''';\s*throw'
        $pattern = $reset + '\s*if\s*\(' + [regex]::Escape($Condition) + '\)\s*\{\s*' + $rejection
        $script:transportSource | Should -Match $pattern
    }
    It 'resets successful factory and complete cleanup metadata rather than retaining a completed operation' {
        $reset = '\$Diagnostic\.Code\s*=\s*''UnexpectedFailure'';\s*\$Diagnostic\.Predicate\s*=\s*''UnexpectedFailure'''
        $script:transportFactorySource | Should -Match ($reset + '\s*return\s+\$handler')
        $script:transportSource | Should -Match ('\$client\.Dispose\(\)\s*if\s*\(-not\s*\$failed\)\s*\{\s*' + $reset + '\s*\}')
    }
    It 'keeps factory-only constructor and policy diagnostics fixed without ever executing that factory' {
        $actual = @([regex]::Matches($script:transportFactorySource, '\$Diagnostic\.Predicate\s*=\s*''(Transport[A-Za-z0-9]+)''') | ForEach-Object { $_.Groups[1].Value })
        ($actual -join ',') | Should -BeExactly 'TransportHandlerConstruction,TransportRedirectPolicy,TransportCookiePolicy,TransportCredentialPolicy,TransportProxyPolicy'
        $script:transportFactorySource | Should -Match "(?s)'TransportHandlerConstruction'\s*;?\s*\`$handler\s*=\s*\[Net\.Http\.HttpClientHandler\]::new\(\)"
        foreach ($pair in @(
            @('TransportRedirectPolicy', 'AllowAutoRedirect'), @('TransportCookiePolicy', 'UseCookies'),
            @('TransportCredentialPolicy', 'UseDefaultCredentials'), @('TransportProxyPolicy', 'UseProxy')
        )) {
            $pattern = "'" + $pair[0] + "'\s*;\s*\`$handler\." + $pair[1] + '\s*=\s*\$false'
            $script:transportFactorySource | Should -Match $pattern
        }
        # Runtime policy-setting faults would require loading a real factory
        # or replacing sealed/nonvirtual framework behavior. This assertion is
        # deliberately static and is not presented as native fault coverage.
    }
    It 'places every otherwise uninjectable framework operation directly after its entered label: <Predicate>' -ForEach @(
        @{ Predicate = 'TransportTimeoutConfiguration'; Operation = '$client.Timeout = [TimeSpan]::FromSeconds(30)' },
        @{ Predicate = 'TransportRequestConstruction'; Operation = '$request = [Net.Http.HttpRequestMessage]::new($httpMethod, $target)' },
        @{ Predicate = 'TransportBufferConstruction'; Operation = '$buffer = [IO.MemoryStream]::new()' },
        @{ Predicate = 'TransportBodyConstruction'; Operation = '$request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, ''application/x-www-form-urlencoded'')' },
        @{ Predicate = 'TransportDeadlineConstruction'; Operation = '$cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(30))' },
        @{ Predicate = 'TransportReadBufferConstruction'; Operation = '$bytes = [byte[]]::new(4096)' },
        @{ Predicate = 'TransportLocationRead'; Operation = 'if ($response.Headers.TryGetValues(''Location'', [ref]$values)) { $locations = @($values) }' },
        @{ Predicate = 'TransportResponseProjection'; Operation = '$result = @{ Status = [int]$response.StatusCode; Locations = $locations; ContentType = [string]$response.Content.Headers.ContentType.MediaType }' }
    ) {
        $pattern = '\$Diagnostic\.Predicate\s*=\s*''' + $Predicate + '''\s*;?\s*' + [regex]::Escape($Operation)
        $script:transportSource | Should -Match $pattern
    }
    It 'guards every cleanup label with the same first-failure flag and leaves disposal order unchanged' {
        $script:transportSource | Should -Match 'catch\s*\{\s*\$failed\s*=\s*\$true;\s*throw\s*''Session probe transport failed; sensitive response suppressed\.''\s*\}'
        $expected = @(
            @('TransportStreamDispose', 'stream'), @('TransportResponseDispose', 'response'),
            @('TransportDeadlineDispose', 'cancel'), @('TransportBufferDispose', 'buffer'),
            @('TransportRequestDispose', 'request'), @('TransportClientDispose', 'client')
        )
        $lastIndex = -1
        foreach ($pair in $expected) {
            $pattern = 'if\s*\(-not\s*\$failed\)\s*\{\s*\$Diagnostic\.Code\s*=\s*''TransportFailure'';\s*\$Diagnostic\.Predicate\s*=\s*''' + $pair[0] + '''\s*\}\s*\$' + $pair[1] + '\.Dispose\(\)'
            $match = [regex]::Match($script:transportSource, $pattern)
            $match.Success | Should -BeTrue
            $match.Index | Should -BeGreaterThan $lastIndex
            $lastIndex = $match.Index
        }
        # CancellationTokenSource and MemoryStream are created directly and
        # have no safe fixture hook for Dispose exceptions. The exact guarded
        # call order above is their static coverage, not a fabricated runtime
        # failure, timing guarantee, or real transport test.
    }
}

Describe 'Pinned baseline versus candidate native fake-handler behavior' {
    BeforeEach {
        Mock New-LabProbeHttpHandler {
            switch ($script:transportDifferentialFactory) {
                'Throw' { throw 'fixture-sensitive-handler-creation' }
                'Null' { return $null }
                default { return $script:transportFixture }
            }
        }
        Mock New-BaselineLabProbeHttpHandler {
            switch ($script:transportDifferentialFactory) {
                'Throw' { throw 'fixture-sensitive-handler-creation' }
                'Null' { return $null }
                default { return $script:transportFixture }
            }
        }
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline differential tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline differential tests.' }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'preserves acceptance, full output shape, request fields, bounded reads and disposal for <_>' -ForEach @(
        'Get', 'Post', 'Redirect', 'UriConstruction', 'Scheme', 'Port', 'UserInfo', 'Fragment', 'Host', 'LoginHostSuffix', 'GraphHostSuffix', 'FileUri',
        'Headers', 'Method', 'FactoryThrow', 'FactoryNull', 'Send', 'SendCancel', 'Open', 'OpenCancel',
        'Read', 'ReadCancel', 'AdvertisedLimit', 'ExactLimit', 'StreamedLimit', 'MisleadingLimit', 'BufferWrite', 'Utf8',
        'StreamDispose', 'ResponseDispose', 'RequestDispose', 'ClientDispose',
        'ReadThenStreamDispose', 'ReadThenResponseDispose', 'ReadThenRequestDispose', 'ReadThenClientDispose',
        'Utf8ThenResponseDispose', 'SendThenClientDispose'
    ) {
        $caseName = $_
        $baseline = Get-TransportDifferentialSnapshot Send-BaselineLabProbeRequest $caseName
        $candidate = Get-TransportDifferentialSnapshot Send-LabProbeRequest $caseName
        $candidate | Should -BeExactly $baseline
        # The comparison intentionally includes any pre-exception output from
        # successful-body/failed-cleanup cases. Only the public probe boundary
        # promises zero output and a sanitized error on every failure.
    }
}
