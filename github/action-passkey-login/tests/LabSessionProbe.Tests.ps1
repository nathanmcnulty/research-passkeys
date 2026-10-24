# Offline fixtures only. The native transport is inspected as source but is
# deliberately NEVER loaded or invoked, even if a Pester mock is absent.
BeforeAll {
    $script:probeSource = Get-Content (Join-Path $PSScriptRoot '../.github/validation/LabSessionProbe.ps1') -Raw
    $parseTokens = $null; $parseErrors = $null
    $script:probeAst = [Management.Automation.Language.Parser]::ParseInput($script:probeSource, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Session probe source must parse before offline fixtures load.' }
    $definitions = @($script:probeAst.EndBlock.Statements)
    if ($script:probeAst.BeginBlock -or $script:probeAst.ProcessBlock -or $script:probeAst.ParamBlock -or
        @($definitions | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -ne 0) {
        throw 'Offline fixture permits only top-level function declarations.'
    }
    $transport = @($definitions | Where-Object Name -CEQ 'Send-LabProbeRequest')
    if ($transport.Count -ne 1) { throw 'Expected exactly one isolated native transport.' }
    $factory = @($definitions | Where-Object Name -CEQ 'New-LabProbeHttpHandler')
    if ($factory.Count -ne 1) { throw 'Expected exactly one excluded native handler factory.' }
    $script:probeTransportSource = $transport[0].Extent.Text + $factory[0].Extent.Text
    foreach ($definition in $definitions) {
        if ($definition.Name -cin @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) { continue }
        # Block direct native networking outside the excluded transport. Cmdlet
        # transports also have throwing Pester guards below.
        if ($definition.Extent.Text -match '(?i)HttpClient|HttpWebRequest|WebClient|TcpClient|Socket|SendAsync|DownloadString|Start-Process|Invoke-Expression') {
            throw 'Network-capable code outside the excluded transport is not allowed in the offline harness.'
        }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Send-LabProbeRequest {
        param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body)
        throw 'Native HTTP is unavailable in this offline test suite.'
    }
    function ConvertTo-ProbeTestSegment {
        param([string]$Text)
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    function New-ProbeTestJsonResponse {
        param([string]$Stage, $Value)
        $response = @{ Status = 200; Locations = @(); ContentType = 'application/json'; Body = ($Value | ConvertTo-Json -Depth 16 -Compress) }
        if ($script:probeResponseOverrides.Contains($Stage)) {
            foreach ($key in $script:probeResponseOverrides[$Stage].Keys) { $response[$key] = $script:probeResponseOverrides[$Stage][$key] }
        }
        return $response
    }
    function Set-ProbeTestProperties {
        param($Value, $Overrides, [string[]]$Remove = @())
        foreach ($key in $Overrides.Keys) { $Value[$key] = $Overrides[$key] }
        foreach ($key in $Remove) { [void]$Value.Remove($key) }
    }
    function Invoke-ProbeTest {
        Invoke-LabSessionProbe @script:probeArguments
    }
    $script:probeSafeError = 'Server-backed session probe failed; no live acceptance. Sensitive details suppressed.'
}

Describe 'Server-backed session readback with synthetic, offline evidence' {
    BeforeEach {
        $script:probeArguments = @{
            TenantId = '11111111-1111-4111-8111-111111111111'
            ClientId = '22222222-2222-4222-8222-222222222222'
            ExpectedUpn = 'fixture@example.invalid'
            CookieName = 'ESTSAUTH'
            Cookie = 'synthetic-cookie-never-a-real-credential'
        }
        $script:probeAuthority = 'https://login.microsoftonline.com/' + $script:probeArguments.TenantId
        $script:probeRedirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        $script:probeDiscovery = $script:probeAuthority + '/v2.0/.well-known/openid-configuration'
        $script:probeAuthorizeEndpoint = $script:probeAuthority + '/oauth2/v2.0/authorize'
        $script:probeTokenEndpoint = $script:probeAuthority + '/oauth2/v2.0/token'
        $script:probeUserInfoEndpoint = 'https://graph.microsoft.com/oidc/userinfo'
        $script:probeRequests = [Collections.Generic.List[object]]::new()
        $script:probeAuthorizeQuery = $null
        $script:probeAuthorizeCount = 0
        $script:probeCallbackMode = 'success'
        $script:probeRedirectOverride = $null
        $script:probeThrowStage = ''
        $script:probeMetadataOverrides = @{}
        $script:probeMetadataRemove = @()
        $script:probeHeaderOverrides = @{}
        $script:probeClaimsOverrides = @{}
        $script:probeClaimsRemove = @()
        $script:probeTokenOverrides = @{}
        $script:probeTokenRemove = @()
        $script:probeUserInfoOverrides = @{}
        $script:probeUserInfoRemove = @()
        $script:probeResponseOverrides = @{}
        $script:probeRawHeader = $null
        $script:probeRawClaims = $null
        $script:probeIdTokenMode = ''
        $script:probeSignature = 'c3ludGhldGljLXNpZ25hdHVyZQ'
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline session tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline session tests.' }
        Mock Send-LabProbeRequest {
            param($Uri, $Method = 'GET', $Headers = @{}, $Body)
            if ($null -eq $Headers) { $Headers = @{} }
            $script:probeRequests.Add(@{ Uri = [string]$Uri; Method = $Method; Headers = @{} + $Headers; Body = $Body })
            if ($Uri -ceq $script:probeDiscovery) {
                if ($script:probeThrowStage -eq 'Discovery') { throw 'fixture-sensitive-discovery-detail' }
                $metadata = @{
                    issuer = $script:probeAuthority + '/v2.0'
                    authorization_endpoint = $script:probeAuthorizeEndpoint
                    token_endpoint = $script:probeTokenEndpoint
                    userinfo_endpoint = $script:probeUserInfoEndpoint
                }
                Set-ProbeTestProperties $metadata $script:probeMetadataOverrides $script:probeMetadataRemove
                return New-ProbeTestJsonResponse Discovery $metadata
            }
            if ($Uri.StartsWith($script:probeAuthorizeEndpoint + '?', [StringComparison]::Ordinal)) {
                if ($script:probeThrowStage -eq 'Authorization') { throw 'fixture-sensitive-cookie-detail' }
                $script:probeAuthorizeCount++
                if ($null -eq $script:probeAuthorizeQuery) { $script:probeAuthorizeQuery = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query) }
                $state = [uri]::EscapeDataString($script:probeAuthorizeQuery['state'])
                $query = "code=synthetic-authorization-code&state=$state"
                switch ($script:probeCallbackMode) {
                    'missing-state' { $query = 'code=synthetic-authorization-code' }
                    'wrong-state' { $query = 'code=synthetic-authorization-code&state=wrong-state' }
                    'empty-state' { $query = 'code=synthetic-authorization-code&state=' }
                    'duplicate-state' { $query += "&state=$state" }
                    'encoded-duplicate-state' { $query += "&st%61te=$state" }
                    'case-duplicate-state' { $query += "&STATE=$state" }
                    'missing-code' { $query = "state=$state" }
                    'empty-code' { $query = "state=$state&code=" }
                    'blank-code' { $query = "state=$state&code=%20%20" }
                    'duplicate-code' { $query += '&code=second-code' }
                    'encoded-duplicate-code' { $query += '&co%64e=second-code' }
                    'case-duplicate-code' { $query += '&CODE=second-code' }
                    'oversize-code' { $query = "state=$state&code=" + ('x' * 16385) }
                    'unnamed-field' { $query += '&unkeyed-value' }
                    'duplicate-extra-field' { $query += '&extra=one&extra=two' }
                    'login-required' { $query += '&error=login_required&error_description=fixture-sensitive-login-detail' }
                    'interaction-required' { $query += '&error=interaction_required' }
                    'consent-required' { $query += '&error=consent_required' }
                    'access-denied' { $query += '&error=access_denied' }
                }
                $location = $script:probeRedirect + '?' + $query
                if ($script:probeCallbackMode -eq 'loop') { $location = $Uri }
                if ($null -ne $script:probeRedirectOverride) { $location = $script:probeRedirectOverride }
                $response = @{ Status = 302; Locations = @($location); ContentType = 'text/html'; Body = '' }
                if ($script:probeResponseOverrides.Contains('Authorization')) {
                    foreach ($key in $script:probeResponseOverrides.Authorization.Keys) { $response[$key] = $script:probeResponseOverrides.Authorization[$key] }
                }
                return $response
            }
            if ($Uri -ceq $script:probeTokenEndpoint) {
                if ($script:probeThrowStage -eq 'Token') { throw 'fixture-sensitive-code-and-token-detail' }
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $header = @{ alg = 'RS256'; typ = 'JWT'; kid = 'synthetic-only' }
                $claims = @{
                    iss = $script:probeAuthority + '/v2.0'; tid = $script:probeArguments.TenantId
                    aud = $script:probeArguments.ClientId; nonce = $script:probeAuthorizeQuery['nonce']
                    oid = '33333333-3333-4333-8333-333333333333'; sub = 'synthetic-pairwise-subject'
                    preferred_username = 'fixture@example.invalid'; iat = $now; exp = $now + 600
                }
                Set-ProbeTestProperties $header $script:probeHeaderOverrides
                Set-ProbeTestProperties $claims $script:probeClaimsOverrides $script:probeClaimsRemove
                $headerJson = $header | ConvertTo-Json -Depth 16 -Compress
                $claimsJson = $claims | ConvertTo-Json -Depth 16 -Compress
                if ($null -ne $script:probeRawHeader) { $headerJson = $script:probeRawHeader }
                if ($null -ne $script:probeRawClaims) { $claimsJson = $script:probeRawClaims }
                $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.' + $script:probeSignature
                switch ($script:probeIdTokenMode) {
                    'opaque' { $idToken = 'opaque-not-an-id-token' }
                    'empty' { $idToken = '' }
                    'two-parts' { $idToken = 'e30.e30' }
                    'four-parts' { $idToken += '.fourth' }
                    'empty-header' { $idToken = '.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'empty-payload' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '..c2ln' }
                    'invalid-header-alphabet' { $idToken = '!!!.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-alphabet' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.!!!.c2ln' }
                    'invalid-header-length' { $idToken = 'a.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-length' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.a.c2ln' }
                    'invalid-header-utf8' { $idToken = '_w.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-utf8' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '._w.c2ln' }
                    'empty-signature' { $idToken = $idToken.Substring(0, $idToken.LastIndexOf('.') + 1) }
                    'invalid-signature-alphabet' { $idToken = $idToken.Substring(0, $idToken.LastIndexOf('.') + 1) + '!!!' }
                }
                $tokens = @{ token_type = 'Bearer'; access_token = 'synthetic-opaque-access-token'; id_token = $idToken }
                Set-ProbeTestProperties $tokens $script:probeTokenOverrides $script:probeTokenRemove
                return New-ProbeTestJsonResponse Token $tokens
            }
            if ($Uri -ceq $script:probeUserInfoEndpoint) {
                if ($script:probeThrowStage -eq 'UserInfo') { throw 'fixture-sensitive-userinfo-detail' }
                $user = @{ sub = 'synthetic-pairwise-subject'; name = 'Synthetic fixture only' }
                Set-ProbeTestProperties $user $script:probeUserInfoOverrides $script:probeUserInfoRemove
                return New-ProbeTestJsonResponse UserInfo $user
            }
            throw 'Offline fixture refused an unexpected destination; no HTTP was attempted.'
        }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'returns only the bounded receipt after a synthetic current-transaction ID token and matching UserInfo' {
        $result = Invoke-ProbeTest
        $result.ServerBackedSessionReuse | Should -BeTrue
        $result.ExpectedTenantAndCurrentName | Should -BeTrue
        $result.UserInfoSubjectMatched | Should -BeTrue
        $result.TamperProofAgainstCandidate | Should -BeFalse
        (@($result.Keys) | Sort-Object) -join ',' | Should -BeExactly 'ExpectedTenantAndCurrentName,ServerBackedSessionReuse,TamperProofAgainstCandidate,UserInfoSubjectMatched'
        ($result | ConvertTo-Json -Compress) | Should -Not -Match 'synthetic|fixture@example|11111111|22222222|33333333'
        Should -Invoke Send-LabProbeRequest -Times 4 -Exactly
    }
    It 'binds state, nonce and S256 PKCE and requests only silent openid profile authorization' {
        $null = Invoke-ProbeTest
        $query = $script:probeAuthorizeQuery
        $query['scope'] | Should -BeExactly 'openid profile'
        $query['prompt'] | Should -BeExactly 'none'
        $query['response_type'] | Should -BeExactly 'code'
        $query['response_mode'] | Should -BeExactly 'query'
        $query['client_id'] | Should -BeExactly $script:probeArguments.ClientId
        $query['redirect_uri'] | Should -BeExactly $script:probeRedirect
        $query['code_challenge_method'] | Should -BeExactly 'S256'
        $query['state'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $query['nonce'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $query['state'] | Should -Not -BeExactly $query['nonce']
        (@($query.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code_challenge,code_challenge_method,nonce,prompt,redirect_uri,response_mode,response_type,scope,state'
        $request = $script:probeRequests[2]
        $request.Method | Should -BeExactly 'POST'
        $request.Uri | Should -BeExactly $script:probeTokenEndpoint
        $form = [Web.HttpUtility]::ParseQueryString($request.Body)
        $form['grant_type'] | Should -BeExactly 'authorization_code'
        $form['client_id'] | Should -BeExactly $script:probeArguments.ClientId
        $form['redirect_uri'] | Should -BeExactly $script:probeRedirect
        $form['scope'] | Should -BeExactly 'openid profile'
        $form['code'] | Should -BeExactly 'synthetic-authorization-code'
        $form['code_verifier'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $expectedChallenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($form['code_verifier']))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $query['code_challenge'] | Should -BeExactly $expectedChallenge
        (@($form.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code,code_verifier,grant_type,redirect_uri,scope'
        $request.Body | Should -Not -Match 'refresh_token|offline_access|client_secret'
    }
    It 'sends the cookie only to authorization and the opaque bearer only to UserInfo' {
        $null = Invoke-ProbeTest
        $script:probeRequests[0].Headers.Count | Should -Be 0
        $script:probeRequests[1].Headers.Count | Should -Be 1
        $script:probeRequests[1].Headers.Cookie | Should -BeExactly ('ESTSAUTH=' + $script:probeArguments.Cookie)
        $script:probeRequests[2].Headers.Count | Should -Be 0
        $script:probeRequests[3].Uri | Should -BeExactly $script:probeUserInfoEndpoint
        $script:probeRequests[3].Headers.Count | Should -Be 1
        $script:probeRequests[3].Headers.Authorization | Should -BeExactly 'Bearer synthetic-opaque-access-token'
        foreach ($request in $script:probeRequests) {
            $request.Uri | Should -Not -Match 'synthetic-cookie|synthetic-opaque-access-token|fixture@example'
        }
    }
    It 'uses distinct state, nonce and verifier for a new transaction' {
        $null = Invoke-ProbeTest
        $firstQuery = $script:probeAuthorizeQuery
        $firstVerifier = ([Web.HttpUtility]::ParseQueryString($script:probeRequests[2].Body))['code_verifier']
        $script:probeAuthorizeQuery = $null
        $null = Invoke-ProbeTest
        $script:probeAuthorizeQuery['state'] | Should -Not -BeExactly $firstQuery['state']
        $script:probeAuthorizeQuery['nonce'] | Should -Not -BeExactly $firstQuery['nonce']
        ([Web.HttpUtility]::ParseQueryString($script:probeRequests[6].Body))['code_verifier'] | Should -Not -BeExactly $firstVerifier
    }
    It 'accepts the other explicitly permitted cookie name without changing its boundary' {
        $script:probeArguments.CookieName = 'ESTSAUTHPERSISTENT'
        $null = Invoke-ProbeTest
        $script:probeRequests[1].Headers.Cookie | Should -BeExactly ('ESTSAUTHPERSISTENT=' + $script:probeArguments.Cookie)
    }
    It 'accepts a current UPN case variation, matching authorized party, and present valid nbf' {
        $script:probeClaimsOverrides = @{ preferred_username = 'FIXTURE@EXAMPLE.INVALID'; azp = $script:probeArguments.ClientId; nbf = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1 }
        (Invoke-ProbeTest).UserInfoSubjectMatched | Should -BeTrue
    }
    It 'accepts a 303 callback without following the nativeclient URL' {
        $script:probeResponseOverrides.Authorization = @{ Status = 303 }
        $null = Invoke-ProbeTest
        @($script:probeRequests | Where-Object { $_.Uri.StartsWith($script:probeRedirect) }).Count | Should -Be 0
    }

    It 'requires explicit <Field> before any request' -ForEach @('TenantId', 'ClientId', 'ExpectedUpn') {
        [void]$script:probeArguments.Remove($_)
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects malformed tenant/client IDs before HTTP: <Value>' -ForEach @('', 'organizations', 'common', '00000000-0000-0000-0000-000000000000', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', "11111111-1111-4111-8111-111111111111`n", '11111111-1111-4111-8111-111111111111/extra') {
        foreach ($field in @('TenantId', 'ClientId')) {
            $original = $script:probeArguments[$field]
            $script:probeArguments[$field] = $_
            { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
            $script:probeArguments[$field] = $original
        }
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'permits an explicitly selected common-client compatibility scenario without assuming live support' -ForEach @('04b07795-8ddb-461a-bbee-02f9e1bf7b46', '14d82eec-204b-4c2f-b7e8-296a70dab67e') {
        { Assert-LabProbeConfiguration $script:probeArguments.TenantId $_ $script:probeArguments.ExpectedUpn } | Should -Not -Throw
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects missing or malformed expected UPNs' -ForEach @('', 'fixture', 'fixture@@example.invalid', ' fixture@example.invalid', "fixture@example.invalid`n", (('x' * 310) + '@example.invalid')) {
        $script:probeArguments.ExpectedUpn = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects invalid cookie material without any request' -ForEach @('', "cookie`nvalue", "cookie`rvalue", 'cookie;second=value', 'cookie,value', 'cookie value', 'cookie"value', 'cookie\value', ('x' * 32769)) {
        $script:probeArguments.Cookie = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects absent or unknown cookie names' -ForEach @('', 'estsauth', 'OTHER', "ESTSAUTH`r`nInjected: x") {
        $script:probeArguments.CookieName = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }

    It 'requires every pinned discovery endpoint: <_>' -ForEach @('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint') {
        $script:probeMetadataRemove = @($_)
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 1 -Exactly
    }
    It 'rejects alternate or non-string discovery metadata: <Field>' -ForEach @(
        @{ Field = 'issuer'; Value = 'https://login.microsoftonline.com/common/v2.0' },
        @{ Field = 'issuer'; Value = @('https://login.microsoftonline.com/common/v2.0') },
        @{ Field = 'authorization_endpoint'; Value = 'https://example.invalid/authorize' },
        @{ Field = 'token_endpoint'; Value = 'https://login.microsoftonline.com/common/oauth2/v2.0/token' },
        @{ Field = 'userinfo_endpoint'; Value = 'https://graph.microsoft.com/v1.0/me' },
        @{ Field = 'userinfo_endpoint'; Value = $null }
    ) {
        $script:probeMetadataOverrides[$Field] = $Value
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 1 -Exactly
    }
    It 'rejects a trailing slash, query, fragment or extra path on every pinned discovery value' -ForEach @(@{Suffix='/'}, @{Suffix='?extra=1'}, @{Suffix='#fragment'}, @{Suffix='/extra'}) {
        foreach ($field in @('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint')) {
            $base = switch ($field) {
                'issuer' { $script:probeAuthority + '/v2.0' }
                'authorization_endpoint' { $script:probeAuthorizeEndpoint }
                'token_endpoint' { $script:probeTokenEndpoint }
                'userinfo_endpoint' { $script:probeUserInfoEndpoint }
            }
            $script:probeMetadataOverrides = @{ $field = $base + $Suffix }
            { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        }
    }
    It 'rejects invalid status, media type, redirect or JSON at <Stage>' -ForEach @(
        @{ Stage = 'Discovery'; Change = @{ Status = 302; Locations = @('https://example.invalid/discovery') } },
        @{ Stage = 'Discovery'; Change = @{ ContentType = 'text/html' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '{not-json' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '[]' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '{"issuer":"one","ISSUER":"two"}' } },
        @{ Stage = 'Token'; Change = @{ Status = 302; Locations = @('https://example.invalid/token') } },
        @{ Stage = 'Token'; Change = @{ Status = 400 } },
        @{ Stage = 'Token'; Change = @{ ContentType = 'text/html' } },
        @{ Stage = 'Token'; Change = @{ Locations = @('https://example.invalid/unexpected') } },
        @{ Stage = 'Token'; Change = @{ Body = 'null' } },
        @{ Stage = 'Token'; Change = @{ Body = '{"token_type":"Bearer","TOKEN_TYPE":"Bearer"}' } },
        @{ Stage = 'UserInfo'; Change = @{ Status = 302; Locations = @('https://example.invalid/userinfo') } },
        @{ Stage = 'UserInfo'; Change = @{ Status = 401 } },
        @{ Stage = 'UserInfo'; Change = @{ ContentType = 'text/plain' } },
        @{ Stage = 'UserInfo'; Change = @{ Body = '[{"sub":"synthetic-pairwise-subject"}]' } },
        @{ Stage = 'UserInfo'; Change = @{ Body = '{"sub":"one","SUB":"two"}' } }
    ) {
        $script:probeResponseOverrides[$Stage] = $Change
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        @($script:probeRequests | Where-Object { $_.Uri.StartsWith('https://example.invalid') }).Count | Should -Be 0
    }

    It 'rejects interactive pages, unexpected authorization status, or ambiguous location headers' -ForEach @(
        @{ Change = @{ Status = 200; Body = '<form>Consent or interactive login</form>' } },
        @{ Change = @{ Status = 401 } },
        @{ Change = @{ Status = 301 } },
        @{ Change = @{ Status = 307 } },
        @{ Change = @{ Status = 308 } },
        @{ Change = @{ Locations = @() } },
        @{ Change = @{ Locations = @('https://login.microsoftonline.com/common/oauth2/nativeclient', 'https://example.invalid/') } }
    ) {
        $script:probeResponseOverrides.Authorization = $Change
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
    }
    It 'rejects untrusted authorization redirects before forwarding the cookie: <_>' -ForEach @(
        'https://example.invalid/callback', 'http://login.microsoftonline.com/common/oauth2/nativeclient',
        'https://login.microsoftonline.com:444/common/oauth2/nativeclient',
        'https://user@login.microsoftonline.com/common/oauth2/nativeclient',
        'https://login.microsoftonline.com/common/oauth2/nativeclient#fragment',
        'https://login.microsoftonline.com.example.invalid/common/oauth2/nativeclient',
        '//example.invalid/callback', 'file:///tmp/callback', 'https://login.microsoftonline.com/logout',
        'https://login.microsoftonline.com/another-tenant/oauth2/v2.0/authorize'
    ) {
        $script:probeRedirectOverride = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
    }
    It 'does not follow even a same-origin authorization loop' {
        $script:probeCallbackMode = 'loop'
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        $script:probeAuthorizeCount | Should -Be 1
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
        @($script:probeRequests | Where-Object Method -EQ 'POST').Count | Should -Be 0
    }
    It 'rejects ambiguous, unbound or error callback <_> before token exchange' -ForEach @(
        'missing-state', 'wrong-state', 'empty-state', 'duplicate-state', 'encoded-duplicate-state', 'case-duplicate-state',
        'missing-code', 'empty-code', 'blank-code', 'duplicate-code', 'encoded-duplicate-code', 'case-duplicate-code',
        'oversize-code', 'unnamed-field', 'duplicate-extra-field', 'login-required', 'interaction-required', 'consent-required', 'access-denied'
    ) {
        $script:probeCallbackMode = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
        @($script:probeRequests | Where-Object Method -EQ 'POST').Count | Should -Be 0
    }

    It 'accepts only explicit identity-only returned scope strings' -ForEach @('openid profile', 'profile openid', 'openid') {
        $script:probeTokenOverrides.scope = $_
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
    }
    It 'rejects broader or malformed returned scopes' -ForEach @('openid profile User.Read', 'openid offline_access', 'https://graph.microsoft.com/.default', 'OPENID', '', "openid`nprofile", @('openid','profile'), $null) {
        $script:probeTokenOverrides.scope = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }

    It 'requires each token response field: <_>' -ForEach @('id_token', 'access_token', 'token_type') {
        $script:probeTokenRemove = @($_)
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects malformed token response <Field>' -ForEach @(
        @{ Field = 'token_type'; Value = 'PoP' }, @{ Field = 'token_type'; Value = @('Bearer') },
        @{ Field = 'access_token'; Value = '' }, @{ Field = 'access_token'; Value = ' ' },
        @{ Field = 'access_token'; Value = "token`r`nInjected: value" }, @{ Field = 'access_token'; Value = @('token') },
        @{ Field = 'id_token'; Value = @('header.payload.signature') }, @{ Field = 'id_token'; Value = $null },
        @{ Field = 'refresh_token'; Value = 'unrequested-refresh-token' }
    ) {
        $script:probeTokenOverrides[$Field] = $Value
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects an opaque or malformed ID token: <_>' -ForEach @(
        'opaque', 'empty', 'two-parts', 'four-parts', 'empty-header', 'empty-payload',
        'invalid-header-alphabet', 'invalid-payload-alphabet', 'invalid-header-length', 'invalid-payload-length',
        'invalid-header-utf8', 'invalid-payload-utf8', 'empty-signature', 'invalid-signature-alphabet'
    ) {
        $script:probeIdTokenMode = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects unexpected ID-token algorithms: <_>' -ForEach @('none', 'HS256', 'rs256', '', @('RS256')) {
        $script:probeHeaderOverrides.alg = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
    }
    It 'rejects unsupported critical header extensions' -ForEach @(@('custom'), 'custom', $null) {
        $script:probeHeaderOverrides.crit = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
    }
    It 'rejects malformed, non-object or duplicate header/claim JSON: <Part>' -ForEach @(
        @{ Part = 'Header'; Json = '{broken' }, @{ Part = 'Header'; Json = '[]' },
        @{ Part = 'Header'; Json = '{"alg":"RS256","ALG":"RS256"}' },
        @{ Part = 'Claims'; Json = '{broken' }, @{ Part = 'Claims'; Json = '[]' },
        @{ Part = 'Claims'; Json = '{"iss":"one","ISS":"two"}' }
    ) {
        if ($Part -eq 'Header') { $script:probeRawHeader = $Json } else { $script:probeRawClaims = $Json }
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
    }
    It 'requires all identity, transaction and time claims: <_>' -ForEach @('iss', 'tid', 'aud', 'nonce', 'oid', 'preferred_username', 'sub', 'iat', 'exp') {
        $script:probeClaimsRemove = @($_)
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects incorrectly bound or non-string identity claims: <Field>' -ForEach @(
        @{ Field = 'iss'; Value = 'https://login.microsoftonline.com/common/v2.0' },
        @{ Field = 'iss'; Value = @('https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0') },
        @{ Field = 'tid'; Value = '44444444-4444-4444-8444-444444444444' },
        @{ Field = 'tid'; Value = @('11111111-1111-4111-8111-111111111111') },
        @{ Field = 'aud'; Value = '44444444-4444-4444-8444-444444444444' },
        @{ Field = 'aud'; Value = @('22222222-2222-4222-8222-222222222222') },
        @{ Field = 'nonce'; Value = 'replayed-from-another-transaction' }, @{ Field = 'nonce'; Value = @('nonce') },
        @{ Field = 'azp'; Value = '44444444-4444-4444-8444-444444444444' }, @{ Field = 'azp'; Value = @('22222222-2222-4222-8222-222222222222') },
        @{ Field = 'oid'; Value = '' }, @{ Field = 'oid'; Value = '00000000-0000-0000-0000-000000000000' },
        @{ Field = 'oid'; Value = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, @{ Field = 'oid'; Value = @('33333333-3333-4333-8333-333333333333') },
        @{ Field = 'preferred_username'; Value = 'someone-else@example.invalid' }, @{ Field = 'preferred_username'; Value = @('fixture@example.invalid') },
        @{ Field = 'sub'; Value = '' }, @{ Field = 'sub'; Value = ' ' }, @{ Field = 'sub'; Value = @('synthetic-pairwise-subject') }
    ) {
        $script:probeClaimsOverrides[$Field] = $Value
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects non-integer numeric-date claims: <Field>' -ForEach @(
        @{ Field = 'iat'; Value = '1770000000' }, @{ Field = 'iat'; Value = 1.5 }, @{ Field = 'iat'; Value = $true },
        @{ Field = 'exp'; Value = '1770000600' }, @{ Field = 'exp'; Value = 1.5 }, @{ Field = 'exp'; Value = @([long]1770000600) },
        @{ Field = 'nbf'; Value = '1770000000' }, @{ Field = 'nbf'; Value = 1.5 }, @{ Field = 'nbf'; Value = $null }
    ) {
        $script:probeClaimsOverrides[$Field] = $Value
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects expired, stale, future or internally inconsistent token times: <_>' -ForEach @('expired', 'stale-iat', 'future-iat', 'future-nbf', 'exp-before-iat', 'exp-equals-iat') {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        switch ($_) {
            'expired' { $script:probeClaimsOverrides.exp = $now - 10 }
            'stale-iat' { $script:probeClaimsOverrides.iat = $now - 600 }
            'future-iat' { $script:probeClaimsOverrides.iat = $now + 300 }
            'future-nbf' { $script:probeClaimsOverrides.nbf = $now + 300 }
            'exp-before-iat' { $script:probeClaimsOverrides.iat = $now + 30; $script:probeClaimsOverrides.exp = $now + 20 }
            'exp-equals-iat' { $script:probeClaimsOverrides.iat = $now + 30; $script:probeClaimsOverrides.exp = $now + 30 }
        }
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects UserInfo subject mismatch or malformed subject: <_>' -ForEach @('wrong-subject', 'SYNTHETIC-PAIRWISE-SUBJECT', '', ' ', @('synthetic-pairwise-subject'), $null) {
        $script:probeUserInfoOverrides.sub = $_
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
        Should -Invoke Send-LabProbeRequest -Times 4 -Exactly
    }
    It 'rejects missing UserInfo subject even when another user field matches' {
        $script:probeUserInfoRemove = @('sub')
        $script:probeUserInfoOverrides.preferred_username = 'fixture@example.invalid'
        { Invoke-ProbeTest } | Should -Throw $script:probeSafeError
    }
    It 'suppresses secret-bearing transport details and emits no partial receipt: <_>' -ForEach @('Discovery', 'Authorization', 'Token', 'UserInfo') {
        $script:probeThrowStage = $_
        $messages = [Collections.Generic.List[object]]::new()
        $caught = $null
        try { Invoke-ProbeTest *>&1 | ForEach-Object { $messages.Add($_) } } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly $script:probeSafeError
        $messages.Count | Should -Be 0
        $caught.ToString() | Should -Not -Match 'fixture-sensitive|synthetic-cookie|synthetic-authorization|synthetic-opaque|fixture@example'
    }
}

Describe 'Native transport is inspected but never executed' {
    # These source contracts do not establish real HttpClient timeout, TLS,
    # streaming-limit or redirect behavior. A separate fake HttpMessageHandler
    # injection seam would be needed to exercise those behaviors without HTTP.
    It 'has only one explicit, fully replaced HTTP boundary' {
        (Get-Command Send-LabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Match 'Native HTTP is unavailable'
        (Get-Command Send-LabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Not -Match 'HttpClient|SendAsync'
    }
    It 'forbids automatic redirects, ambient cookies, credentials and proxies in native source' {
        foreach ($setting in @('AllowAutoRedirect', 'UseCookies', 'UseDefaultCredentials', 'UseProxy')) {
            $script:probeTransportSource | Should -Match ('\.' + $setting + '\s*=\s*\$false')
            $script:probeTransportSource | Should -Not -Match ('\.' + $setting + '\s*=\s*\$true')
        }
        $script:probeTransportSource | Should -Not -Match 'ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificateValidator|DefaultNetworkCredentials|CredentialCache|CookieContainer'
    }
    It 'pins HTTPS destinations and bounds response time and size without fetching metadata or JWKS elsewhere' {
        $script:probeTransportSource | Should -Match "Scheme\s+-cne\s+'https'"
        $script:probeTransportSource | Should -Match 'Port\s+-ne\s+443'
        $script:probeTransportSource | Should -Match 'login\.microsoftonline\.com'
        $script:probeTransportSource | Should -Match 'graph\.microsoft\.com'
        $script:probeTransportSource | Should -Match '\.UserInfo'
        $script:probeTransportSource | Should -Match '\.Fragment'
        $script:probeTransportSource | Should -Match 'FromSeconds\(30\)'
        $script:probeTransportSource | Should -Match '65536'
        $script:probeTransportSource | Should -Match 'CancellationTokenSource'
        $script:probeTransportSource | Should -Match 'sensitive response suppressed'
    }
    It 'does not accept caller-supplied tokens or expose a general token-refresh interface' {
        $names = (Get-Command Invoke-LabSessionProbe).Parameters.Keys
        foreach ($forbidden in @('IdToken', 'AccessToken', 'RefreshToken', 'ClientSecret', 'Credential')) {
            $names | Should -Not -Contain $forbidden
        }
        $script:probeSource | Should -Not -Match 'grant_type\s*=\s*[''"]refresh_token|scope\s*=\s*[''"][^''"]*offline_access'
        $script:probeSource | Should -Match 'OIDC Core 3\.1\.3\.7 step 6'
        $script:probeSource | Should -Match 'TamperProofAgainstCandidate\s*=\s*\$false'
    }
}
