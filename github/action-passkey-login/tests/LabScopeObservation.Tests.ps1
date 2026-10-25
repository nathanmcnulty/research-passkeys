# Synthetic, offline observations only. This file is source-reviewed before any
# parser or Pester execution. The loader below never loads the native handler or
# transport, and does not import the production file as a whole.
BeforeAll {
    $script:scopeProbeSource = Get-Content (Join-Path $PSScriptRoot '../.github/validation/LabSessionProbe.ps1') -Raw
    $tokens = $null; $errors = $null
    $script:scopeProbeAst = [Management.Automation.Language.Parser]::ParseInput($script:scopeProbeSource, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'Probe source must parse before the isolated offline fixture loads.' }
    $script:scopeDefinitions = @($script:scopeProbeAst.EndBlock.Statements)
    if ($script:scopeProbeAst.BeginBlock -or $script:scopeProbeAst.ProcessBlock -or $script:scopeProbeAst.ParamBlock -or
        @($script:scopeDefinitions | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -ne 0) {
        throw 'Only top-level function declarations are permitted in this offline fixture.'
    }
    foreach ($excluded in @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) {
        if (@($script:scopeDefinitions | Where-Object Name -CEQ $excluded).Count -ne 1) {
            throw 'Both native networking definitions must be present and excluded.'
        }
    }
    foreach ($definition in $script:scopeDefinitions) {
        if ($definition.Name -cin @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) { continue }
        if ($definition.Extent.Text -match '(?i)HttpClient|HttpWebRequest|WebClient|TcpClient|Socket|SendAsync|DownloadString|Start-Process|Invoke-Expression') {
            throw 'Network-capable code outside the excluded transport is forbidden.'
        }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Send-LabProbeRequest {
        param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body, [hashtable]$Diagnostic)
        throw 'Native HTTP is unavailable in this offline observation test suite.'
    }
    function ConvertTo-ScopeTestSegment {
        param([string]$Text)
        return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    function New-ScopeTestAccessToken {
        param([string]$Payload = '{"scp":"User.Read"}', [string]$Header = '{"alg":"none"}')
        # Deliberately not a valid signature: observations MUST NOT claim validation.
        return (ConvertTo-ScopeTestSegment $Header) + '.' + (ConvertTo-ScopeTestSegment $Payload) + '.c3ludGhldGlj'
    }
    function New-ScopeTestJsonResponse {
        param($Value)
        return @{ Status = 200; Locations = @(); ContentType = 'application/json'; Body = (ConvertTo-Json -InputObject $Value -Depth 16 -Compress) }
    }
    function Get-ScopeTestErrorRendering {
        param($Record)
        if ($null -eq $Record) { return '' }
        return @($Record.ToString(), $Record.Exception.ToString(), ($Record | Out-String),
            ($Record | Format-List * -Force | Out-String), ($Record.Exception | Format-List * -Force | Out-String),
            ($Record.Exception.Data | Out-String), [string]$Record.TargetObject, [string]$Record.ErrorDetails,
            [string]$Record.FullyQualifiedErrorId, [string]$Record.CategoryInfo, [string]$Record.ScriptStackTrace,
            [string]$Record.InvocationInfo.PositionMessage) -join "`n"
    }
    function Invoke-ScopeTestCapture {
        param([scriptblock]$Action)
        $messages = [Collections.Generic.List[object]]::new(); $caught = $null
        $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; $InformationPreference = 'Continue'; $WarningPreference = 'Continue'
        try { & $Action *>&1 | ForEach-Object { $messages.Add($_) } } catch { $caught = $_ }
        return @{ Messages = $messages; Error = $caught; ErrorRendering = (Get-ScopeTestErrorRendering $caught) }
    }
    function Assert-ScopeTestReaderResult {
        param($Result, [string]$Status, [string[]]$Names = @())
        ($Result -is [Collections.IDictionary]) | Should -BeTrue
        (@($Result.Keys) | Sort-Object) -join ',' | Should -BeExactly 'Names,Status'
        $Result.Status | Should -BeExactly $Status
        ($Result.Names -is [string[]]) | Should -BeTrue
        $Result.Names.Count | Should -Be $Names.Count
        for ($index = 0; $index -lt $Names.Count; $index++) { $Result.Names[$index] | Should -BeExactly $Names[$index] }
        if ($Status -cne 'Available') { $Result.Names.Count | Should -Be 0 }
    }
    function Assert-ScopeTestSnapshot {
        param($Snapshot, [string]$ResponseStatus, [string]$AccessStatus,
            [string[]]$ResponseNames = @(), [string[]]$AccessNames = @())
        ($Snapshot -is [Collections.IDictionary]) | Should -BeTrue
        (@($Snapshot.Keys) | Sort-Object) -join ',' | Should -BeExactly 'AccessTokenScp,ResponseScope'
        foreach ($key in @('ResponseScope', 'AccessTokenScp')) {
            $observation = $Snapshot[$key]
            ($observation -is [Collections.IDictionary]) | Should -BeTrue
            (@($observation.Keys) | Sort-Object) -join ',' | Should -BeExactly 'Names,ObservedAtUtc,Provenance,Status'
            ($observation.Names -is [string[]]) | Should -BeTrue
            $observation.ObservedAtUtc | Should -Match '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}\+00:00\z'
            $parsed = [DateTimeOffset]::ParseExact($observation.ObservedAtUtc, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None)
            $parsed.Offset | Should -Be ([TimeSpan]::Zero)
            $parsed | Should -BeGreaterOrEqual $script:scopeTestEarliest
            $parsed | Should -BeLessOrEqual ([DateTimeOffset]::UtcNow)
        }
        $Snapshot.ResponseScope.Provenance | Should -BeExactly 'TokenResponseScope'
        $Snapshot.AccessTokenScp.Provenance | Should -BeExactly 'UnverifiedAccessTokenScp'
        $Snapshot.ResponseScope.ObservedAtUtc | Should -BeExactly $Snapshot.AccessTokenScp.ObservedAtUtc
        Assert-ScopeTestReaderResult @{ Status = $Snapshot.ResponseScope.Status; Names = $Snapshot.ResponseScope.Names } $ResponseStatus $ResponseNames
        Assert-ScopeTestReaderResult @{ Status = $Snapshot.AccessTokenScp.Status; Names = $Snapshot.AccessTokenScp.Names } $AccessStatus $AccessNames
    }
    function Invoke-ScopeTestProbe {
        param([bool]$Observe = $true, [switch]$ExplicitNull)
        $script:scopeInvocationArguments = @{} + $script:scopeProbeArguments
        if ($Observe) { $script:scopeInvocationArguments.ScopeObservation = $script:scopeOutput }
        if ($ExplicitNull) { $script:scopeInvocationArguments.ScopeObservation = $null }
        return Invoke-ScopeTestCapture { Invoke-LabSessionProbe @script:scopeInvocationArguments }
    }
    function Assert-ScopeTestSuccessfulProbe {
        param($Captured)
        $Captured.Error | Should -BeNullOrEmpty
        $Captured.ErrorRendering | Should -BeExactly ''
        # Captures success, error, warning, verbose, debug and information streams.
        $Captured.Messages.Count | Should -Be 1
        (ConvertTo-Json -InputObject $Captured.Messages[0] -Compress) | Should -BeExactly '{"ServerBackedSessionReuse":true,"ExpectedTenantAndCurrentName":true,"UserInfoSubjectMatched":true,"TamperProofAgainstCandidate":false}'
        $script:scopeRequests.Count | Should -Be 4
        $script:scopeBeforeUserInfoCount | Should -Be 0
        (@($script:scopeRequests | ForEach-Object Method) -join ',') | Should -BeExactly 'GET,GET,POST,GET'
        $script:scopeRequests[0].Uri | Should -BeExactly ($script:scopeAuthority + '/v2.0/.well-known/openid-configuration')
        $script:scopeRequests[2].Uri | Should -BeExactly ($script:scopeAuthority + '/oauth2/v2.0/token')
        $script:scopeRequests[3].Uri | Should -BeExactly 'https://graph.microsoft.com/oidc/userinfo'
        $script:scopeAuthorization['scope'] | Should -BeExactly 'openid profile'
        $script:scopeAuthorization['prompt'] | Should -BeExactly 'none'
        $form = [Web.HttpUtility]::ParseQueryString($script:scopeRequests[2].Body)
        $form['scope'] | Should -BeExactly 'openid profile'
        $form['grant_type'] | Should -BeExactly 'authorization_code'
        (@($script:scopeAuthorization.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code_challenge,code_challenge_method,nonce,prompt,redirect_uri,response_mode,response_type,scope,state'
        (@($form.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code,code_verifier,grant_type,redirect_uri,scope'
        $script:scopeRequests[3].Headers.Authorization | Should -BeExactly ('Bearer ' + $script:scopeAccessToken)
    }
    function Assert-ScopeTestNoSecrets {
        param($Captured, $Snapshot)
        $visible = @((ConvertTo-Json -InputObject $Captured.Messages.ToArray() -Depth 16 -Compress),
            $Captured.ErrorRendering, ($Captured.Messages | Out-String),
            (ConvertTo-Json -InputObject $Snapshot -Depth 16 -Compress)) -join "`n"
        $visible | Should -Not -Match 'scope-secret|synthetic-cookie|synthetic-authorization|fixture@example|11111111-1111|22222222-2222|33333333-3333'
        $secrets = @($script:scopeAccessToken, $script:scopeIdToken)
        if ($null -ne $script:scopeAuthorization) { $secrets += @($script:scopeAuthorization['nonce'], $script:scopeAuthorization['state']) }
        foreach ($secret in $secrets) {
            if ($secret) { $visible.Contains([string]$secret) | Should -BeFalse }
        }
    }
}

Describe 'Bounded scope name representation is separate from token acceptance' {
    It 'preserves ASCII name order, case, periods, underscores, hyphens and duplicates' {
        $captured = Invoke-ScopeTestCapture { ConvertTo-LabProbeScopeNames 'User.Read openid User.Read user.read A_b-C.9' }
        $captured.Error | Should -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 1
        Assert-ScopeTestReaderResult $captured.Messages[0] Available @('User.Read', 'openid', 'User.Read', 'user.read', 'A_b-C.9')
    }
    It 'rejects the whole source without filtering or coercion: <Case>' -ForEach @(
        @{ Case = 'null'; Value = $null }
        @{ Case = 'integer'; Value = 7 }
        @{ Case = 'boolean'; Value = $true }
        @{ Case = 'array'; Value = @('User.Read', 'openid') }
        @{ Case = 'dictionary'; Value = @{ scope = 'User.Read' } }
        @{ Case = 'empty'; Value = '' }
        @{ Case = 'leading space'; Value = ' User.Read' }
        @{ Case = 'trailing space'; Value = 'User.Read ' }
        @{ Case = 'double space'; Value = 'User.Read  openid' }
        @{ Case = 'URL shaped'; Value = 'User.Read https://graph.microsoft.com/.default openid' }
        @{ Case = 'colon'; Value = 'User.Read x:y openid' }
        @{ Case = 'plus'; Value = 'User.Read A+B openid' }
        @{ Case = 'slash'; Value = 'User.Read A/B openid' }
        @{ Case = 'backslash'; Value = 'User.Read A\B openid' }
        @{ Case = 'leading digit'; Value = 'User.Read 1read openid' }
        @{ Case = 'leading dot'; Value = 'User.Read .read openid' }
        @{ Case = 'leading underscore'; Value = 'User.Read _read openid' }
        @{ Case = 'leading hyphen'; Value = 'User.Read -read openid' }
        @{ Case = 'quote'; Value = 'User.Read A"B openid' }
        @{ Case = 'angle brackets'; Value = 'User.Read <script> openid' }
    ) {
        $script:scopeInvalidValue = $Value
        $captured = Invoke-ScopeTestCapture { ConvertTo-LabProbeScopeNames $script:scopeInvalidValue }
        $captured.Error | Should -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 1
        Assert-ScopeTestReaderResult $captured.Messages[0] Unavailable
    }
    It 'rejects all ASCII controls, DEL, Unicode separators, formatting, non-ASCII and lone surrogates' {
        foreach ($codePoint in @((0..31) + @(127, 128, 133, 160, 233, 0x200B, 0x200D, 0x2028, 0x2029, 0x202E, 0x2066, 0xD800, 0xDC00, 0xFEFF))) {
            $script:scopeInvalidValue = 'Read ' + 'A' + [char]$codePoint + 'B' + ' openid'
            $captured = Invoke-ScopeTestCapture { ConvertTo-LabProbeScopeNames $script:scopeInvalidValue }
            $captured.Error | Should -BeNullOrEmpty
            $captured.Messages.Count | Should -Be 1
            Assert-ScopeTestReaderResult $captured.Messages[0] Unavailable
        }
    }
    It 'accepts exactly 128 characters per name and refuses 129 without truncation' {
        $name = 'A' + ('a' * 127)
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames $name) Available @($name)
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames ($name + 'a')) Unavailable
    }
    It 'accepts 64 duplicate names and refuses the 65th rather than deduplicating' {
        $names = [string[]](@('Read') * 64)
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames ($names -join ' ')) Available $names
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames ((@('Read') * 65) -join ' ')) Unavailable
    }
    It 'accepts exactly 4096 source characters and refuses 4097 without partial results' {
        $name = 'A' + ('a' * 127)
        $names = [string[]]((@($name) * 31) + @('B' + ('b' * 96)))
        $source = $names -join ' '
        $source.Length | Should -Be 4096
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames $source) Available $names
        Assert-ScopeTestReaderResult (ConvertTo-LabProbeScopeNames ($source + 'b')) Unavailable
    }
}

Describe 'Unverified access-token scp observation with strict bounded representation' {
    It 'extracts only exact scp and never treats other JWT claims as verified' {
        $token = New-ScopeTestAccessToken '{"scp":"Read read Read","roles":["scope-secret-role"],"aud":"scope-secret-audience","iss":"scope-secret-issuer","sub":"scope-secret-subject","exp":1,"iat":9999999999,"nonce":"scope-secret-nonce","name":"scope-secret-name"}'
        $result = Read-LabProbeAccessTokenScopes $token
        Assert-ScopeTestReaderResult $result Available @('Read', 'read', 'Read')
        (ConvertTo-Json -InputObject $result -Compress) | Should -Not -Match 'scope-secret|aud|iss|sub|exp|iat|nonce|token'
    }
    It 'reports Absent for an object without exact-case scp: <Case>' -ForEach @(
        @{ Case = 'empty object'; Payload = '{}' }
        @{ Case = 'uppercase SCP'; Payload = '{"SCP":"Read"}' }
        @{ Case = 'mixed Scp'; Payload = '{"Scp":"Read"}' }
        @{ Case = 'scope instead'; Payload = '{"scope":"Read"}' }
        @{ Case = 'nested scp'; Payload = '{"nested":{"scp":"Read"}}' }
        @{ Case = 'roles only'; Payload = '{"roles":["Read"]}' }
    ) {
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $Payload)) Absent
    }
    It 'recognizes the JSON-unescaped exact property name' {
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"\u0073cp":"Read"}')) Available @('Read')
    }
    It 'returns Unavailable for wrong types, malformed JSON and duplicate top-level keys: <Case>' -ForEach @(
        @{ Case = 'null scp'; Payload = '{"scp":null}' }
        @{ Case = 'array scp'; Payload = '{"scp":["Read"]}' }
        @{ Case = 'number scp'; Payload = '{"scp":4}' }
        @{ Case = 'boolean scp'; Payload = '{"scp":true}' }
        @{ Case = 'object scp'; Payload = '{"scp":{"name":"Read"}}' }
        @{ Case = 'empty scp'; Payload = '{"scp":""}' }
        @{ Case = 'unsafe scp all-or-nothing'; Payload = '{"scp":"Read https://graph.microsoft.com/.default openid"}' }
        @{ Case = 'root array'; Payload = '[]' }
        @{ Case = 'root string'; Payload = '"Read"' }
        @{ Case = 'root null'; Payload = 'null' }
        @{ Case = 'root number'; Payload = '1' }
        @{ Case = 'truncated object'; Payload = '{"scp":"Read"' }
        @{ Case = 'trailing data'; Payload = '{"scp":"Read"}{}' }
        @{ Case = 'trailing comma'; Payload = '{"scp":"Read",}' }
        @{ Case = 'comment'; Payload = '{/*comment*/"scp":"Read"}' }
        @{ Case = 'duplicate scp'; Payload = '{"scp":"Read","scp":"Write"}' }
        @{ Case = 'case duplicate scp'; Payload = '{"scp":"Read","SCP":"Write"}' }
        @{ Case = 'escaped duplicate scp'; Payload = '{"scp":"Read","\u0073cp":"Write"}' }
        @{ Case = 'unrelated duplicate'; Payload = '{"scp":"Read","other":1,"other":2}' }
        @{ Case = 'unrelated case duplicate'; Payload = '{"scp":"Read","other":1,"OTHER":2}' }
        @{ Case = 'duplicates even without scp'; Payload = '{"other":1,"OTHER":2}' }
        @{ Case = 'tab in scp'; Payload = '{"scp":"Read\topenid"}' }
        @{ Case = 'newline in scp'; Payload = '{"scp":"Read\nopenid"}' }
        @{ Case = 'null in scp'; Payload = '{"scp":"Read\u0000openid"}' }
        @{ Case = 'Unicode in scp'; Payload = '{"scp":"R\u00e9ad"}' }
        @{ Case = 'bidi in scp'; Payload = '{"scp":"R\u202ead"}' }
        @{ Case = 'paired surrogate in scp'; Payload = '{"scp":"R\ud83d\ude00ead"}' }
        @{ Case = 'lone high surrogate'; Payload = '{"scp":"R\ud800ead"}' }
        @{ Case = 'lone low surrogate'; Payload = '{"scp":"R\udc00ead"}' }
    ) {
        $script:scopeMalformedToken = New-ScopeTestAccessToken $Payload
        $captured = Invoke-ScopeTestCapture { Read-LabProbeAccessTokenScopes $script:scopeMalformedToken }
        $captured.Error | Should -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 1
        Assert-ScopeTestReaderResult $captured.Messages[0] Unavailable
    }
    It 'returns Unavailable for non-JWT, invalid base64url and strict UTF-8 failures: <Case>' -ForEach @(
        @{ Case = 'null'; Token = $null }
        @{ Case = 'integer'; Token = 42 }
        @{ Case = 'boolean'; Token = $true }
        @{ Case = 'array'; Token = @('e30.e30.c2ln') }
        @{ Case = 'dictionary'; Token = @{ token = 'e30.e30.c2ln' } }
        @{ Case = 'empty'; Token = '' }
        @{ Case = 'opaque'; Token = 'scope-secret-opaque-token' }
        @{ Case = 'two parts'; Token = 'e30.e30' }
        @{ Case = 'four parts'; Token = 'e30.e30.c2ln.e30' }
        @{ Case = 'empty header'; Token = '.e30.c2ln' }
        @{ Case = 'empty payload'; Token = 'e30..c2ln' }
        @{ Case = 'empty signature'; Token = 'e30.e30.' }
        @{ Case = 'padding'; Token = 'e30.e30=.c2ln' }
        @{ Case = 'standard plus alphabet'; Token = 'e30.e+0.c2ln' }
        @{ Case = 'standard slash alphabet'; Token = 'e30.e/0.c2ln' }
        @{ Case = 'whitespace'; Token = 'e30.e 0.c2ln' }
        @{ Case = 'payload impossible length'; Token = 'e30.A.c2ln' }
        @{ Case = 'header impossible length'; Token = 'A.e30.c2ln' }
        @{ Case = 'signature impossible length'; Token = 'e30.e30.A' }
        @{ Case = 'invalid header UTF-8'; Token = '_w.e30.c2ln' }
        @{ Case = 'invalid UTF-8 byte'; Token = 'e30._w.c2ln' }
        @{ Case = 'overlong UTF-8'; Token = 'e30.wK8.c2ln' }
        @{ Case = 'UTF-8 encoded surrogate'; Token = 'e30.7aCA.c2ln' }
        @{ Case = 'signature punctuation'; Token = 'e30.e30.sig!' }
        @{ Case = 'header punctuation'; Token = '!30.e30.c2ln' }
    ) {
        $script:scopeMalformedToken = $Token
        $captured = Invoke-ScopeTestCapture { Read-LabProbeAccessTokenScopes $script:scopeMalformedToken }
        $captured.Error | Should -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 1
        Assert-ScopeTestReaderResult $captured.Messages[0] Unavailable
        (ConvertTo-Json -InputObject $captured.Messages.ToArray() -Compress) | Should -Not -Match 'scope-secret'
    }
    It 'treats header structure as representation only, not signature or algorithm validation' {
        foreach ($header in @('{}', '{"alg":"none"}', '{"alg":"HS256","kid":"scope-secret-untrusted-key"}', '{"alg":null,"typ":7}')) {
            Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $header)) Available @('Read')
        }
    }
    It 'rejects malformed or ambiguous header objects without throwing: <Case>' -ForEach @(
        @{ Case = 'root array'; Header = '[]' }
        @{ Case = 'root null'; Header = 'null' }
        @{ Case = 'root string'; Header = '"scope-secret-header"' }
        @{ Case = 'malformed'; Header = '{"scope-secret-header":' }
        @{ Case = 'duplicate'; Header = '{"alg":"none","alg":"HS256"}' }
        @{ Case = 'case duplicate'; Header = '{"alg":"none","ALG":"HS256"}' }
        @{ Case = 'escaped duplicate'; Header = '{"alg":"none","\u0061lg":"HS256"}' }
        @{ Case = 'unrelated duplicate'; Header = '{"other":1,"OTHER":2}' }
    ) {
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $Header)) Unavailable
    }
    It 'bounds total access-token characters at 16384 before extraction' {
        $prefix = (ConvertTo-ScopeTestSegment '{}') + '.' + (ConvertTo-ScopeTestSegment '{"scp":"Read"}') + '.'
        $atLimit = $prefix + ('A' * (16384 - $prefix.Length))
        $atLimit.Length | Should -Be 16384
        # The boundary signature has a representable base64url length too.
        (($atLimit.Split('.')[2].Length % 4) -ne 1) | Should -BeTrue
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes $atLimit) Available @('Read')
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes ($atLimit + 'A')) Unavailable
    }
    It 'bounds decoded payload bytes at 8192, independently of whole-token length' {
        $prefix = '{"scp":"Read","unused":"'; $suffix = '"}'
        $payload = $prefix + ('x' * (8192 - $prefix.Length - $suffix.Length)) + $suffix
        [Text.Encoding]::UTF8.GetByteCount($payload) | Should -Be 8192
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Available @('Read')
        $oversize = $prefix + ('x' * (8193 - $prefix.Length - $suffix.Length)) + $suffix
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $oversize)) Unavailable
    }
    It 'counts decoded UTF-8 bytes rather than JSON characters for the payload limit' {
        $prefix = '{"scp":"Read","unused":"'; $suffix = '"}'
        $payload = $prefix + ([string][char]0x00E9 * 4100) + $suffix
        $payload.Length | Should -BeLessThan 8192
        [Text.Encoding]::UTF8.GetByteCount($payload) | Should -BeGreaterThan 8192
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Unavailable
    }
    It 'also bounds the decoded header at 8192 bytes' {
        $prefix = '{"unused":"'; $suffix = '"}'
        $header = $prefix + ('x' * (8192 - $prefix.Length - $suffix.Length)) + $suffix
        [Text.Encoding]::UTF8.GetByteCount($header) | Should -Be 8192
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $header)) Available @('Read')
        $header = $prefix + ('x' * (8193 - $prefix.Length - $suffix.Length)) + $suffix
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $header)) Unavailable
    }
    It 'bounds JSON nesting at depth 16 even for ignored fields' {
        $atLimit = '{"scp":"Read","unused":' + ('{"x":' * 15) + '0' + ('}' * 15) + '}'
        $overLimit = '{"scp":"Read","unused":' + ('{"x":' * 16) + '0' + ('}' * 16) + '}'
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $atLimit)) Available @('Read')
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $overLimit)) Unavailable
    }
    It 'also bounds ignored header nesting at depth 16' {
        $atLimit = '{"unused":' + ('{"x":' * 15) + '0' + ('}' * 15) + '}'
        $overLimit = '{"unused":' + ('{"x":' * 16) + '0' + ('}' * 16) + '}'
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $atLimit)) Available @('Read')
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken '{"scp":"Read"}' $overLimit)) Unavailable
    }
    It 'applies source, name and duplicate-count limits inside scp without truncation' {
        foreach ($value in @(('A' + ('a' * 128)), ((@('Read') * 65) -join ' '), ('A' * 4097))) {
            $payload = ConvertTo-Json -InputObject @{ scp = $value } -Compress
            Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Unavailable
        }
        $names = [string[]](@('Read') * 64)
        $payload = ConvertTo-Json -InputObject @{ scp = ($names -join ' ') } -Compress
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Available $names
        $name = 'A' + ('a' * 127)
        $payload = ConvertTo-Json -InputObject @{ scp = $name } -Compress
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Available @($name)
        $names = [string[]]((@($name) * 31) + @('B' + ('b' * 96)))
        $value = $names -join ' '
        $value.Length | Should -Be 4096
        $payload = ConvertTo-Json -InputObject @{ scp = $value } -Compress
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Available $names
        $payload = ConvertTo-Json -InputObject @{ scp = ($value + 'b') } -Compress
        Assert-ScopeTestReaderResult (Read-LabProbeAccessTokenScopes (New-ScopeTestAccessToken $payload)) Unavailable
    }
}

Describe 'Separate local scope snapshots do not change server-backed probe acceptance' {
    BeforeEach {
        $script:scopeTestEarliest = [DateTimeOffset]::UtcNow
        $script:scopeProbeArguments = @{
            TenantId = '11111111-1111-4111-8111-111111111111'; ClientId = '22222222-2222-4222-8222-222222222222'
            ExpectedUpn = 'fixture@example.invalid'; CookieName = 'ESTSAUTH'; Cookie = 'synthetic-cookie-never-real'
        }
        $script:scopeAuthority = 'https://login.microsoftonline.com/' + $script:scopeProbeArguments.TenantId
        $script:scopeRedirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        $script:scopeRequests = [Collections.Generic.List[object]]::new()
        $script:scopeOutput = [Collections.Generic.List[object]]::new()
        $script:scopeAuthorization = $null; $script:scopeBeforeUserInfoCount = -1; $script:scopeIdToken = $null
        $script:scopeResponsePresent = $true; $script:scopeResponseValue = 'openid User.Read openid'
        $script:scopeAccessToken = New-ScopeTestAccessToken '{"scp":"Mail.Read User.Read Mail.Read","aud":"scope-secret-audience","sub":"scope-secret-access-subject","iat":1,"exp":2,"metadata":{"name":"scope-secret-metadata"}}'
        $script:scopeFailureStage = ''
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline scope observation tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline scope observation tests.' }
        Mock Send-LabProbeRequest {
            param($Uri, $Method = 'GET', $Headers = @{}, $Body, [hashtable]$Diagnostic)
            $script:scopeRequests.Add(@{ Uri = [string]$Uri; Method = $Method; Headers = @{} + $Headers; Body = $Body })
            if ($Uri -ceq ($script:scopeAuthority + '/v2.0/.well-known/openid-configuration')) {
                if ($script:scopeFailureStage -ceq 'DiscoveryTransport') { throw 'scope-secret-discovery-error' }
                $metadata = @{
                    issuer = $script:scopeAuthority + '/v2.0'
                    authorization_endpoint = $script:scopeAuthority + '/oauth2/v2.0/authorize'
                    token_endpoint = $script:scopeAuthority + '/oauth2/v2.0/token'
                    userinfo_endpoint = 'https://graph.microsoft.com/oidc/userinfo'
                }
                if ($script:scopeFailureStage -ceq 'DiscoveryMetadata') { $metadata.issuer = 'scope-secret-wrong-issuer' }
                return New-ScopeTestJsonResponse $metadata
            }
            if ($Uri.StartsWith($script:scopeAuthority + '/oauth2/v2.0/authorize?', [StringComparison]::Ordinal)) {
                $script:scopeAuthorization = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)
                $state = [uri]::EscapeDataString($script:scopeAuthorization['state'])
                if ($script:scopeFailureStage -ceq 'Callback') { $state = 'scope-secret-wrong-state' }
                $status = 302
                if ($script:scopeFailureStage -ceq 'Authorization') { $status = 200 }
                return @{ Status = $status; Locations = @($script:scopeRedirect + '?code=synthetic-authorization-code&state=' + $state); ContentType = 'text/html'; Body = 'scope-secret-authorize-body' }
            }
            if ($Uri -ceq ($script:scopeAuthority + '/oauth2/v2.0/token')) {
                if ($script:scopeFailureStage -ceq 'TokenTransport') { throw 'scope-secret-token-error' }
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $claims = @{
                    iss = $script:scopeAuthority + '/v2.0'; tid = $script:scopeProbeArguments.TenantId
                    aud = $script:scopeProbeArguments.ClientId; nonce = $script:scopeAuthorization['nonce']
                    oid = '33333333-3333-4333-8333-333333333333'; sub = 'scope-secret-identity-subject'
                    preferred_username = 'fixture@example.invalid'; iat = $now; exp = $now + 600
                }
                if ($script:scopeFailureStage -ceq 'IdBinding') { $claims.aud = 'scope-secret-wrong-audience' }
                if ($script:scopeFailureStage -ceq 'TokenTimes') { $claims.exp = 1 }
                $script:scopeIdToken = (ConvertTo-ScopeTestSegment '{"alg":"RS256","kid":"scope-secret-key-id"}') + '.' +
                    (ConvertTo-ScopeTestSegment (ConvertTo-Json -InputObject $claims -Compress)) + '.c3ludGhldGlj'
                if ($script:scopeFailureStage -ceq 'IdEncoding') { $script:scopeIdToken = 'scope-secret-not-a-jwt' }
                $response = @{ token_type = 'Bearer'; access_token = $script:scopeAccessToken; id_token = $script:scopeIdToken; ignored = 'scope-secret-token-metadata' }
                if ($script:scopeResponsePresent) { $response.scope = $script:scopeResponseValue }
                if ($script:scopeFailureStage -ceq 'TokenResponse') { $response.token_type = 'scope-secret-not-bearer' }
                return New-ScopeTestJsonResponse $response
            }
            if ($Uri -ceq 'https://graph.microsoft.com/oidc/userinfo') {
                $script:scopeBeforeUserInfoCount = $script:scopeOutput.Count
                if ($script:scopeFailureStage -ceq 'UserInfoTransport') { throw 'scope-secret-userinfo-error' }
                $subject = 'scope-secret-identity-subject'
                if ($script:scopeFailureStage -ceq 'UserInfoSubject') { $subject = 'scope-secret-unmatched-subject' }
                $response = New-ScopeTestJsonResponse @{ sub = $subject; name = 'scope-secret-userinfo-name' }
                if ($script:scopeFailureStage -ceq 'UserInfoResponse') { $response.Body = '["scope-secret-invalid-userinfo"]' }
                return $response
            }
            throw 'Offline scope fixture refused an unexpected destination; no HTTP was attempted.'
        }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'keeps the ordinary receipt unchanged and emits one bounded snapshot only through the opted-in container' {
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 1
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Available Available @('openid', 'User.Read', 'openid') @('Mail.Read', 'User.Read', 'Mail.Read')
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'retains a valid narrow-name canary only in the opted-in in-memory snapshot: <Observe>' -ForEach @(
        @{ Observe = $false }
        @{ Observe = $true }
    ) {
        # Grammar is a representation boundary, NOT semantic redaction: a string
        # that resembles a secret but satisfies that grammar is still a name.
        $script:scopeResponseValue = 'ScopeSecretCanary openid ScopeSecretCanary'
        $script:scopeAccessToken = New-ScopeTestAccessToken '{"scp":"ScopeSecretCanary Read ScopeSecretCanary","other":"scope-secret-ignored"}'
        $captured = Invoke-ScopeTestProbe -Observe $Observe
        Assert-ScopeTestSuccessfulProbe $captured
        (ConvertTo-Json -InputObject $captured.Messages.ToArray() -Depth 8 -Compress) | Should -Not -Match 'ScopeSecretCanary'
        $captured.ErrorRendering | Should -Not -Match 'ScopeSecretCanary'
        if ($Observe) {
            $script:scopeOutput.Count | Should -Be 1
            Assert-ScopeTestSnapshot $script:scopeOutput[0] Available Available @('ScopeSecretCanary', 'openid', 'ScopeSecretCanary') @('ScopeSecretCanary', 'Read', 'ScopeSecretCanary')
        } else { $script:scopeOutput.Count | Should -Be 0 }
    }
    It 'never calls extraction when the observation parameter is omitted or explicitly null' -ForEach @(
        @{ Explicit = $false }
        @{ Explicit = $true }
    ) {
        Mock New-LabProbeScopeObservation { throw 'scope-secret-observation-must-not-run' }
        Mock Read-LabProbeAccessTokenScopes { throw 'scope-secret-decoder-must-not-run' }
        $captured = Invoke-ScopeTestProbe -Observe $false -ExplicitNull:$Explicit
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 0
        Should -Invoke New-LabProbeScopeObservation -Times 0 -Exactly
        Should -Invoke Read-LabProbeAccessTokenScopes -Times 0 -Exactly
        Assert-ScopeTestNoSecrets $captured $null
    }
    It 'clears stale entries before requests, then replaces them with exactly one snapshot' {
        $script:scopeOutput.Add(@{ stale = 'scope-secret-stale-observation' })
        $script:scopeOutput.Add(@{ stale = 'scope-secret-second-stale-observation' })
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 1
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Available Available @('openid', 'User.Read', 'openid') @('Mail.Read', 'User.Read', 'Mail.Read')
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'retains neither the prior snapshot nor partial observations after a failed second transaction' {
        Assert-ScopeTestSuccessfulProbe (Invoke-ScopeTestProbe)
        $script:scopeOutput.Count | Should -Be 1
        $script:scopeProbeArguments.CookieName = 'scope-secret-invalid-cookie-name'
        $captured = Invoke-ScopeTestProbe
        $captured.Error | Should -Not -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 0
        $script:scopeOutput.Count | Should -Be 0
        $script:scopeRequests.Count | Should -Be 4
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput.ToArray()
    }
    It 'does not observe or call later endpoints when acceptance fails: <Stage>' -ForEach @(
        @{ Stage = 'Configuration'; Requests = 0; Phase = 'Configuration' }
        @{ Stage = 'Cookie'; Requests = 0; Phase = 'Cookie' }
        @{ Stage = 'DiscoveryTransport'; Requests = 1; Phase = 'DiscoveryRequest' }
        @{ Stage = 'DiscoveryMetadata'; Requests = 1; Phase = 'DiscoveryMetadata' }
        @{ Stage = 'Authorization'; Requests = 2; Phase = 'AuthorizationResponse' }
        @{ Stage = 'Callback'; Requests = 2; Phase = 'Callback' }
        @{ Stage = 'TokenTransport'; Requests = 3; Phase = 'TokenRequest' }
        @{ Stage = 'TokenResponse'; Requests = 3; Phase = 'TokenResponse' }
        @{ Stage = 'IdEncoding'; Requests = 3; Phase = 'TokenEncoding' }
        @{ Stage = 'IdBinding'; Requests = 3; Phase = 'TokenBinding' }
        @{ Stage = 'TokenTimes'; Requests = 3; Phase = 'TokenTimes' }
        @{ Stage = 'UserInfoTransport'; Requests = 4; Phase = 'UserInfoRequest' }
        @{ Stage = 'UserInfoResponse'; Requests = 4; Phase = 'UserInfoResponse' }
        @{ Stage = 'UserInfoSubject'; Requests = 4; Phase = 'UserInfoSubject' }
    ) {
        $script:scopeFailureStage = $Stage
        if ($Stage -ceq 'Configuration') { $script:scopeProbeArguments.ExpectedUpn = 'scope-secret-invalid-upn' }
        if ($Stage -ceq 'Cookie') { $script:scopeProbeArguments.CookieName = 'scope-secret-invalid-name' }
        $script:scopeOutput.Add(@{ stale = 'scope-secret-stale-observation' })
        Mock New-LabProbeScopeObservation { throw 'scope-secret-extraction-must-not-run' }
        Mock Read-LabProbeAccessTokenScopes { throw 'scope-secret-decoder-must-not-run' }
        $captured = Invoke-ScopeTestProbe
        $captured.Error | Should -Not -BeNullOrEmpty
        $captured.Error.Exception.Message | Should -Match ('\AServer-backed session probe failed; no live acceptance\. Sensitive details suppressed\. Phase=' + $Phase + '; Code=[A-Za-z]+; Predicate=[A-Za-z]+\.\z')
        $captured.Error.Exception.InnerException | Should -BeNullOrEmpty
        $captured.Messages.Count | Should -Be 0
        $script:scopeRequests.Count | Should -Be $Requests
        $script:scopeOutput.Count | Should -Be 0
        Should -Invoke New-LabProbeScopeObservation -Times 0 -Exactly
        Should -Invoke Read-LabProbeAccessTokenScopes -Times 0 -Exactly
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput.ToArray()
    }
    It 'separates missing response scope from an opaque or scp-less access token: <Case>' -ForEach @(
        @{ Case = 'opaque'; Token = 'scope-secret-opaque-access-token'; Status = 'Unavailable' }
        @{ Case = 'empty claims object'; Token = 'e30.e30.c2ln'; Status = 'Absent' }
    ) {
        $script:scopeResponsePresent = $false
        $script:scopeAccessToken = $Token
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 1
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Absent $Status
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'does not invent requested names when returned scope is absent' {
        $script:scopeResponsePresent = $false
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Absent Available @() @('Mail.Read', 'User.Read', 'Mail.Read')
    }
    It 'keeps protocol-valid unsafe or oversized response scopes out of observations without denying acceptance: <Case>' -ForEach @(
        @{ Case = 'URI'; Value = 'openid https://graph.microsoft.com/.default User.Read' }
        @{ Case = 'punctuation'; Value = 'Read A+B openid' }
        @{ Case = 'name over limit'; Value = ('A' * 129) }
        @{ Case = 'source over limit'; Value = ('A' * 4097) }
        @{ Case = 'too many duplicates'; Value = ((@('Read') * 65) -join ' ') }
    ) {
        $script:scopeResponseValue = $Value
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Unavailable Available @() @('Mail.Read', 'User.Read', 'Mail.Read')
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'does not let malformed access-token observation alter acceptance or request count: <Case>' -ForEach @(
        @{ Case = 'wrong scp type'; Payload = '{"scp":["Read"],"other":"scope-secret-json"}' }
        @{ Case = 'unsafe scp'; Payload = '{"scp":"Read https://graph.microsoft.com/.default"}' }
        @{ Case = 'duplicate claims'; Payload = '{"scp":"Read","SCP":"Write"}' }
        @{ Case = 'invalid JSON'; Payload = '{"scope-secret-json":' }
        @{ Case = 'nonobject JSON'; Payload = '["scope-secret-json"]' }
    ) {
        $script:scopeAccessToken = New-ScopeTestAccessToken $Payload
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Available Unavailable @('openid', 'User.Read', 'openid')
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'keeps oversized access-token observations non-fatal through the public probe: <Case>' -ForEach @(
        @{ Case = 'whole token over 16384' }
        @{ Case = 'decoded payload over 8192' }
    ) {
        if ($Case -ceq 'whole token over 16384') {
            $prefix = (ConvertTo-ScopeTestSegment '{}') + '.' + (ConvertTo-ScopeTestSegment '{"scp":"Read"}') + '.'
            # 16386 gives the signature a valid modulo-4 length, so only the
            # total size bound should make the otherwise valid shape unavailable.
            $script:scopeAccessToken = $prefix + ('A' * (16386 - $prefix.Length))
            $script:scopeAccessToken.Length | Should -BeGreaterThan 16384
        } else {
            $prefix = '{"scp":"Read","unused":"'; $suffix = '"}'
            $payload = $prefix + ('x' * (8193 - $prefix.Length - $suffix.Length)) + $suffix
            [Text.Encoding]::UTF8.GetByteCount($payload) | Should -Be 8193
            $script:scopeAccessToken = New-ScopeTestAccessToken $payload
            $script:scopeAccessToken.Length | Should -BeLessThan 16384
        }
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        Assert-ScopeTestSnapshot $script:scopeOutput[0] Available Unavailable @('openid', 'User.Read', 'openid')
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput[0]
    }
    It 'suppresses extraction/projection exceptions without changing the receipt or issuing more requests: <Helper>' -ForEach @(
        @{ Helper = 'New-LabProbeScopeObservation' }
        @{ Helper = 'Read-LabProbeAccessTokenScopes' }
        @{ Helper = 'ConvertTo-LabProbeScopeNames' }
    ) {
        Mock $Helper { throw [InvalidOperationException]::new('scope-secret-observation-failure') }
        $script:scopeOutput.Add(@{ stale = 'scope-secret-stale-observation' })
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 0
        Should -Invoke $Helper -Times 1 -Exactly
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput.ToArray()
    }
    It 'drops partial success output from a projection that later throws' {
        Mock New-LabProbeScopeObservation {
            Write-Output @{ unexpected = 'scope-secret-partial-projection' }
            throw [InvalidOperationException]::new('scope-secret-late-projection-fault')
        }
        $script:scopeOutput.Add(@{ stale = 'scope-secret-stale-observation' })
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 0
        Should -Invoke New-LabProbeScopeObservation -Times 1 -Exactly
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput.ToArray()
    }
    It 'contains an injected local timestamp fault after acceptance without changing the receipt' {
        # Transform only the already-isolated observation definition, replacing
        # its local clock expression. No native factory/transport is loaded.
        $definition = @($script:scopeDefinitions | Where-Object Name -CEQ 'New-LabProbeScopeObservation')[0]
        $clockExpression = "[DateTimeOffset]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)"
        $definition.Extent.Text.Contains($clockExpression) | Should -BeTrue
        $body = $definition.Body.Extent.Text
        $faultBody = $body.Substring(1, $body.Length - 2).Replace($clockExpression, "`$(throw 'scope-secret-local-clock-failure')")
        $script:scopeFaultedClockFunction = [scriptblock]::Create($faultBody)
        Mock New-LabProbeScopeObservation { param($Tokens); & $script:scopeFaultedClockFunction -Tokens $Tokens }
        $script:scopeOutput.Add(@{ stale = 'scope-secret-stale-observation' })
        $captured = Invoke-ScopeTestProbe
        Assert-ScopeTestSuccessfulProbe $captured
        $script:scopeOutput.Count | Should -Be 0
        Should -Invoke New-LabProbeScopeObservation -Times 1 -Exactly
        Assert-ScopeTestNoSecrets $captured $script:scopeOutput.ToArray()
    }
    It 'isolates snapshots from later mutation of source dictionaries' {
        $tokens = @{ scope = 'Read Read'; access_token = (New-ScopeTestAccessToken '{"scp":"Mail.Read"}'); other = 'scope-secret-source' }
        $snapshot = New-LabProbeScopeObservation $tokens
        $tokens.scope = 'Changed'; $tokens.access_token = 'scope-secret-changed-token'; $tokens.other = 'Changed'
        Assert-ScopeTestSnapshot $snapshot Available Available @('Read', 'Read') @('Mail.Read')
        (ConvertTo-Json -InputObject $snapshot -Depth 6 -Compress) | Should -Not -Match 'Changed|scope-secret'
    }
    It 'uses one local UTC timestamp rather than any token or response timestamp' {
        $definition = @($script:scopeDefinitions | Where-Object Name -CEQ 'New-LabProbeScopeObservation')[0]
        $definition.Extent.Text | Should -Match '\[DateTimeOffset\]::UtcNow\.ToString\(''o'',\s*\[Globalization\.CultureInfo\]::InvariantCulture\)'
        $tokens = @{ scope = 'Read'; access_token = (New-ScopeTestAccessToken '{"scp":"Read","iat":1,"exp":2,"ObservedAtUtc":"scope-secret-remote-time"}'); ObservedAtUtc = 'scope-secret-response-time' }
        $snapshot = New-LabProbeScopeObservation $tokens
        Assert-ScopeTestSnapshot $snapshot Available Available @('Read') @('Read')
        (ConvertTo-Json -InputObject $snapshot -Depth 6 -Compress) | Should -Not -Match 'scope-secret'
    }
}

Describe 'Observation-only source boundaries and best-effort cleanup' {
    It 'keeps the current workflow on the non-observing invocation' {
        $workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/validate-lab-cookie.yml') -Raw
        $calls = @($workflow -split "`r?`n" | Where-Object { $_ -match '^\s*\$receipt\s*=\s*Invoke-LabSessionProbe\b' })
        $calls.Count | Should -Be 1
        $calls[0].Trim() | Should -BeExactly '$receipt = Invoke-LabSessionProbe $env:COOKIE $env:COOKIE_NAME $env:LAB_TENANT $env:LAB_CLIENT $env:LAB_UPN'
        $workflow | Should -Not -Match '(?i)ScopeObservation|New-LabProbeScopeObservation|Read-LabProbeAccessTokenScopes'
    }
    It 'places byte cleanup in the finally surrounding decode, size, UTF-8 and JSON checks' {
        # This checks source placement, not actual heap contents or managed-string
        # zeroization. The native transport and factory remain excluded.
        $reader = @($script:scopeDefinitions | Where-Object Name -CEQ 'Read-LabProbeAccessTokenScopes')[0]
        $decodeTries = @($reader.FindAll({
            param($node)
            if ($node -isnot [Management.Automation.Language.TryStatementAst]) { return $false }
            return @($node.Body.Statements | Where-Object {
                $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
                $_.Extent.Text -match '^\$bytes\s*=\s*\[Convert\]::FromBase64String\('
            }).Count -eq 1
        }, $true))
        $decodeTries.Count | Should -Be 1
        $decodeTries[0].Finally | Should -Not -BeNullOrEmpty
        $decodeTries[0].Finally.Extent.Text | Should -Match '\[Array\]::Clear\(\$bytes,\s*0,\s*\$bytes\.Length\)'
        $decodeTries[0].Finally.Extent.Text | Should -Match '\$bytes\s*=\s*\$null'
        $body = $decodeTries[0].Body.Extent.Text
        $body | Should -Match '\$bytes\.Length\s*-gt\s*8192'
        $body | Should -Match '\[Text\.UTF8Encoding\]::new\(\$false,\s*\$true\)'
        $body | Should -Match '\[System\.Text\.Json\.JsonDocument\]::Parse\('
        $outerTry = @($reader.Body.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
        $outerTry.Count | Should -Be 1
        foreach ($name in @('AccessToken', 'parts', 'part', 'encoded', 'json', 'document', 'scp')) {
            $outerTry[0].Finally.Extent.Text | Should -Match ('\$' + $name + '\s*=\s*\$null')
        }
    }
}
