BeforeAll {
    $root = Join-Path $PSScriptRoot '..'
    foreach ($relative in @(
        'src/Common/Encoding.ps1', 'src/Common/Values.ps1',
        'src/Entra/SoftwareBrowserHeaders.ps1', 'src/Entra/SoftwareSession.ps1', 'src/Entra/SoftwareAuthorization.ps1', 'src/Entra/SoftwareAuthentication.ps1',
        'src/Entra/UtilityCookie.ps1', 'src/Entra/UtilityMetadataTransport.ps1',
        'src/Entra/UtilityMetadataCatalog.ps1', 'src/Entra/UtilityMetadataGraph.ps1',
        'src/Public/Get-EntraEstsCookieViaTap.ps1', 'src/Public/Get-EntraPasskeyMetadata.ps1'
    )) { . (Join-Path $root $relative) }

    # Test-only Graph command surfaces. Never import or connect an actual Graph module.
    function Get-MgContext { [CmdletBinding()]param(); throw 'Unmocked Graph read is forbidden.' }
    function Get-MgPolicyAuthenticationMethodPolicy { [CmdletBinding()]param(); throw 'Unmocked Graph read is forbidden.' }
    function Get-MgReportAuthenticationMethodUserRegistrationDetail {
        [CmdletBinding()]param([string]$Filter, [switch]$All); throw 'Unmocked Graph read is forbidden.'
    }
    function Get-MgUserAuthenticationFido2Method {
        [CmdletBinding()]param([string]$UserId, [switch]$All); throw 'Unmocked Graph read is forbidden.'
    }
    $known = '11111111-1111-1111-1111-111111111111'
    $unknown = '22222222-2222-2222-2222-222222222222'
    $tenant = [guid]'33333333-3333-3333-3333-333333333333'
    $userId = '44444444-4444-4444-4444-444444444444'
    $fixture = @{ entries = @(@{ aaguid = $known; metadataStatement = @{ aaguid = $known; description = 'Synthetic authenticator' } }) }
    $fixtureJwt = 'e30.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($fixture | ConvertTo-Json -Depth 10 -Compress)))) + '.c2lnbmF0dXJl'
}

Describe 'TAP cookie input and output boundaries' {
    BeforeEach {
        Mock Invoke-EntraRegistrationWebRequest { throw 'Live authentication is forbidden.' }
        Mock Invoke-EntraRegistrationRestMethod { throw 'Live authentication is forbidden.' }
        $script:capturedContext = $null
        Mock Invoke-EntraRegistrationTapAuthentication {
            $script:capturedContext = $Context
            $Context.TenantId = '33333333-3333-3333-3333-333333333333'
            $Context.Token = 'synthetic-token'; $Context.RefreshToken = 'synthetic-refresh-token'
            $Context.WebSession.Cookies.Add([Net.Cookie]::new('ESTSAUTH', 'synthetic-cookie', '/', '.login.microsoftonline.com'))
            $Context
        }
        $tap = ConvertTo-SecureString 'synthetic-tap' -AsPlainText -Force
    }

    It 'requires a secure TAP and has no hardcoded identity or secret defaults' {
        $command = Get-Command Get-EntraEstsCookieViaTap
        @($command.Parameters['TenantId'].Attributes | Where-Object { $_ -is [Management.Automation.ParameterAttribute] })[0].Mandatory | Should -BeFalse
        $command.Parameters['TAP'].ParameterType | Should -Be ([Security.SecureString])
        foreach ($name in @('TAP', 'UserPrincipalName')) {
            @($command.Parameters[$name].Attributes | Where-Object { $_ -is [Management.Automation.ParameterAttribute] })[0].Mandatory | Should -BeTrue
        }
        { Get-EntraEstsCookieViaTap -TAP 'plain-secret' -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 0 -Exactly
    }

    It 'rejects an empty tenant or TAP and malformed UPN before authentication' {
        { Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId ([guid]::Empty) } | Should -Throw
        { Get-EntraEstsCookieViaTap -TAP ([Security.SecureString]::new()) -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw
        { Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'bad-upn' -TenantId $tenant } | Should -Throw
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 0 -Exactly
    }

    It 'returns a structured secure cookie and clears transient state' {
        $result = Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant
        $result.TenantId | Should -BeExactly '33333333-3333-3333-3333-333333333333'
        $result.CookieName | Should -BeExactly 'ESTSAUTH'
        $result.CookieValue | Should -BeOfType ([Security.SecureString])
        [Net.NetworkCredential]::new('', $result.CookieValue).Password | Should -BeExactly 'synthetic-cookie'
        $result.Purpose | Should -BeExactly 'SecurityInfoBootstrap'
        $script:capturedContext.WebSession | Should -BeNullOrEmpty
        $script:capturedContext.Token | Should -BeNullOrEmpty
        $script:capturedContext.RefreshToken | Should -BeNullOrEmpty
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 1 -Exactly -ParameterFilter {
            $TAP -is [Security.SecureString] -and $TenantId -eq [guid]'33333333-3333-3333-3333-333333333333' -and $UserPrincipalName -eq 'user@example.test'
        }
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 0 -Exactly
    }

    It 'emits a raw cookie string only on explicit plaintext opt-in' {
        $result = Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant -AsPlainText
        $result | Should -BeOfType ([string])
        $result | Should -BeExactly 'synthetic-cookie'
    }

    It 'refuses a missing cookie and cleans context after authentication errors' {
        Mock Invoke-EntraRegistrationTapAuthentication { $script:capturedContext = $Context; throw 'Synthetic authentication failure.' }
        { Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw '*Synthetic authentication failure*'
        $script:capturedContext.WebSession | Should -BeNullOrEmpty
        Mock Invoke-EntraRegistrationTapAuthentication { $script:capturedContext = $Context; $Context }
        { Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw '*unambiguous*'
        $script:capturedContext.WebSession | Should -BeNullOrEmpty
    }

    It 'uses an exact cookie name and never accepts similarly prefixed credentials' {
        Mock Invoke-EntraRegistrationTapAuthentication {
            $Context.WebSession.Cookies.Add([Net.Cookie]::new('ESTSAUTHUNRELATED', 'synthetic-cookie', '/', '.login.microsoftonline.com'))
            $Context
        }
        { Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw '*unambiguous*'
    }
}

Describe 'Shared TAP session security checks used by the utility' {
    It 'rejects incorrect or duplicated OAuth state without a request' {
        { Get-EntraRegistrationAuthorizationCode -Callback 'https://mysignins.microsoft.com/#code=synthetic&state=wrong' -ExpectedState 'right' } | Should -Throw
        { Get-EntraRegistrationAuthorizationCode -Callback 'https://mysignins.microsoft.com/#code=synthetic&state=right&state=right' -ExpectedState 'right' } | Should -Throw
        Get-EntraRegistrationAuthorizationCode -Callback 'https://mysignins.microsoft.com/#code=synthetic&state=right' -ExpectedState 'right' | Should -BeExactly 'synthetic'
    }

    It 'rejects a consent page rather than submitting it' {
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{StatusCode = 200; Content = '$Config={"pgid":"Consent"};'; Headers = @{}} }
        $context = New-EntraRegistrationContext
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/authorize' } | Should -Throw '*consent*'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }

    It 'stops redirect loops at the fixed bound and refuses foreign origins' {
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{StatusCode = 302; Content = ''; Headers = @{Location = '/loop'}} }
        $context = New-EntraRegistrationContext
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/loop' } | Should -Throw '*redirect limit*'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 15 -Exactly
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{StatusCode = 302; Content = ''; Headers = @{Location = 'https://foreign.example/steal'}} }
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/loop' } | Should -Throw '*allowed HTTPS origins*'
    }

    It 'checks application, tenant and user consistency on the transport-returned token' {
        $client = '19db86c3-b2b9-44cc-b339-36da233a3be2'
        $claims = @{aud=$client; appid=$client; tid=$tenant.ToString(); upn='user@example.test'; exp=[DateTimeOffset]::UtcNow.AddMinutes(5).ToUnixTimeSeconds()}
        $token = 'e30.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress)))) + '.c2ln'
        $identity = Assert-EntraRegistrationTokenBinding -Token $token -ClientId $client -TenantId $tenant.ToString() -UserPrincipalName 'user@example.test'
        $identity.TenantId | Should -Be $tenant.ToString()
        { Assert-EntraRegistrationTokenBinding -Token $token -ClientId $unknown -TenantId $tenant.ToString() -UserPrincipalName 'user@example.test' } | Should -Throw
        { Assert-EntraRegistrationTokenBinding -Token $token -ClientId $client -TenantId $unknown -UserPrincipalName 'user@example.test' } | Should -Throw
        { Assert-EntraRegistrationTokenBinding -Token $token -ClientId $client -TenantId $tenant.ToString() -UserPrincipalName 'other@example.test' } | Should -Throw
    }
}

Describe 'Offline passkey metadata inventory' {
    BeforeEach {
        Mock Invoke-EntraPasskeyMetadataDownload { throw 'Live metadata download is forbidden.' }
        Mock Get-EntraPasskeyMetadataGraphData { throw 'Graph reads require explicit opt-in.' }
    }

    It 'maps normalized allowed and registered fixture GUIDs and retains unknown keys' {
        $result = Get-EntraPasskeyMetadata -MdsPayload $fixture -AllowedAaguid @($known.ToUpperInvariant(), $known) -RegisteredAaguid @($known, $unknown)
        $result.MetadataVerified | Should -BeFalse
        $result.MetadataTrustWarning | Should -Match 'unverified'
        $result.AllowedAaguids.Count | Should -Be 1
        $result.AllowedEntries[0].Description | Should -BeExactly 'Synthetic authenticator'
        $result.RegisteredEntries.Count | Should -Be 2
        $result.RegisteredEntries[1].Aaguid | Should -Be $unknown
        $result.RegisteredEntries[1].MetadataFound | Should -BeFalse
        $result.UsedGraph | Should -BeFalse
        Should -Invoke Invoke-EntraPasskeyMetadataDownload -Times 0 -Exactly
        Should -Invoke Get-EntraPasskeyMetadataGraphData -Times 0 -Exactly
    }

    It 'handles empty fixture inventories without initiating Graph or network access' {
        $result = Get-EntraPasskeyMetadata -MdsPayload @{entries=@()} -AllowedAaguid @() -RegisteredAaguid @()
        $result.CatalogEntries.Count | Should -Be 0
        $result.AllowedEntries.Count | Should -Be 0
        $result.RegisteredEntries.Count | Should -Be 0
    }

    It 'decodes an explicitly supplied JWT without claiming signature validation' {
        $result = Get-EntraPasskeyMetadata -MdsJwt $fixtureJwt -AllowedAaguid $known
        $result.Source | Should -BeExactly 'FixtureJwt'
        $result.MetadataVerified | Should -BeFalse
        $result.AllowedEntries[0].MetadataVerified | Should -BeFalse
        Should -Invoke Invoke-EntraPasskeyMetadataDownload -Times 0 -Exactly
    }

    It 'bounds download arguments and labels downloaded MDS unverified' {
        Mock Invoke-EntraPasskeyMetadataDownload { $fixtureJwt }
        $result = Get-EntraPasskeyMetadata -MaximumMetadataBytes 4096 -DownloadTimeoutSeconds 5
        $result.Source | Should -BeExactly 'https://mds3.fidoalliance.org/'
        $result.MetadataVerified | Should -BeFalse
        Should -Invoke Invoke-EntraPasskeyMetadataDownload -Times 1 -Exactly -ParameterFilter { $MaximumBytes -eq 4096 -and $TimeoutSeconds -eq 5 }
    }

    It 'rejects malformed JWTs, invalid GUIDs, duplicate/mismatched entries and oversized input' {
        { Get-EntraPasskeyMetadata -MdsJwt 'a.b' } | Should -Throw
        { Get-EntraPasskeyMetadata -MdsJwt 'e30.b!ad.c2ln' } | Should -Throw
        { Get-EntraPasskeyMetadata -MdsPayload $fixture -AllowedAaguid 'not-a-guid' } | Should -Throw '*GUID D format*'
        { Get-EntraPasskeyMetadata -MdsPayload @{entries=@($fixture.entries[0], $fixture.entries[0])} } | Should -Throw '*duplicate*'
        { Get-EntraPasskeyMetadata -MdsPayload @{entries=@(@{aaguid=$known; metadataStatement=@{aaguid=$unknown}})} } | Should -Throw '*do not match*'
        { Get-EntraPasskeyMetadata -MdsPayload ('x' * 1025) -MaximumMetadataBytes 1024 } | Should -Throw '*size limit*'
        { Get-EntraPasskeyMetadata -MdsPayload $fixture -MdsJwt $fixtureJwt } | Should -Throw
        Should -Invoke Invoke-EntraPasskeyMetadataDownload -Times 0 -Exactly
    }

    It 'uses Graph only with explicit opt-in and permits explicit arrays to override Graph inventory' {
        Mock Get-EntraPasskeyMetadataGraphData {
            [pscustomobject]@{AllowedAaguids=@($known); RegisteredAaguids=@($unknown); PolicyRestrictions=@{EnforcementType='allow'}}
        }
        $result = Get-EntraPasskeyMetadata -MdsPayload $fixture -UseGraph -RegisteredAaguid @($known)
        $result.UsedGraph | Should -BeTrue
        $result.AllowedAaguids[0] | Should -Be $known
        $result.RegisteredAaguids[0] | Should -Be $known
        Should -Invoke Get-EntraPasskeyMetadataGraphData -Times 1 -Exactly
    }
}

Describe 'Optional Graph metadata reads with synthetic command surfaces' {
    BeforeEach {
        Mock Get-MgContext { [pscustomobject]@{Account='synthetic@example.test'} }
        Mock Get-MgPolicyAuthenticationMethodPolicy {
            [pscustomobject]@{AuthenticationMethodConfigurations=@([pscustomobject]@{Id='Fido2'; AdditionalProperties=@{keyRestrictions=@{isEnforced=$true; enforcementType='allow'; aaGuids=@($known)}}})}
        }
        Mock Get-MgReportAuthenticationMethodUserRegistrationDetail { @([pscustomobject]@{Id=$userId}, [pscustomobject]@{Id=$userId}) }
        Mock Get-MgUserAuthenticationFido2Method { @([pscustomobject]@{AaGuid=$known}, [pscustomobject]@{AaGuid=$known}, [pscustomobject]@{AaGuid=$unknown}) }
    }

    It 'reads policy and registered AAGUIDs without duplicate user requests or returned identifiers' {
        $result = Get-EntraPasskeyMetadataGraphData
        $result.AllowedAaguids[0] | Should -Be $known
        $result.RegisteredAaguids.Count | Should -Be 2
        Should -Invoke Get-MgUserAuthenticationFido2Method -Times 1 -Exactly -ParameterFilter { $UserId -eq '44444444-4444-4444-4444-444444444444' -and $All }
        Should -Invoke Get-MgReportAuthenticationMethodUserRegistrationDetail -Times 1 -Exactly -ParameterFilter { $Filter -eq "methodsRegistered/any(i:i eq 'passKeyDeviceBound')" -and $All }
        ($result | ConvertTo-Json -Depth 10) | Should -Not -Match 'synthetic@example.test|44444444-4444-4444-4444-444444444444'
    }

    It 'does not describe a block list as an allowed list' {
        Mock Get-MgPolicyAuthenticationMethodPolicy {
            [pscustomobject]@{AuthenticationMethodConfigurations=@([pscustomobject]@{Id='Fido2'; KeyRestrictions=@{isEnforced=$true; enforcementType='block'; aaGuids=@($known)}})}
        }
        $result = Get-EntraPasskeyMetadataGraphData
        $result.AllowedAaguids.Count | Should -Be 0
        $result.PolicyRestrictions.EnforcementType | Should -BeExactly 'block'
        $result.PolicyRestrictions.Aaguids[0] | Should -Be $known
    }

    It 'supports an already-connected app-only Graph context with no account name' {
        Mock Get-MgContext { [pscustomobject]@{AuthType='AppOnly'; Account=$null; TenantId=$tenant.ToString()} }
        $result = Get-EntraPasskeyMetadataGraphData
        $result.RegisteredAaguids.Count | Should -Be 2
    }

    It 'fails closed with no connected Graph context and never attempts consent or connection' {
        Mock Get-MgContext { $null }
        { Get-EntraPasskeyMetadataGraphData } | Should -Throw '*No connection or consent was initiated*'
        Should -Invoke Get-MgPolicyAuthenticationMethodPolicy -Times 0 -Exactly
    }
}

Describe 'Utility source and entrypoint structure' {
    It 'keeps each entrypoint a param block and single public-command invocation' {
        foreach ($name in @('Get-EntraEstsCookieViaTap', 'Get-EntraPasskeyMetadata')) {
            $path = Join-Path $root "entrypoints/$name.ps1"
            $text = Get-Content $path -Raw
            $text | Should -Match '^#Requires -Version 7\.6\r?\n\r?\n'
            $tail = ($text -split '# Invoke public command', 2)[1].Trim()
            $tail | Should -BeExactly "$name @PSBoundParameters"
            $tokens=$null; $errors=$null
            $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }

    It 'has no auth, Graph import or global state work at source-load time' {
        foreach ($path in @(Get-ChildItem (Join-Path $root 'src/Entra/Utility*.ps1'), (Join-Path $root 'src/Public/Get-Entra*.ps1'))) {
            $tokens=$null; $errors=$null
            $ast = [Management.Automation.Language.Parser]::ParseFile($path.FullName, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            @($ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count | Should -Be 0
            $ast.Extent.Text | Should -Not -Match '\$global:|Import-Module|Connect-MgGraph'
        }
    }

    It 'disables redirects and cookies and applies cancellation and read limits to public downloads' {
        $source = Get-Content (Join-Path $root 'src/Entra/UtilityMetadataTransport.ps1') -Raw
        $source | Should -Match '\$handler\.AllowAutoRedirect = \$false'
        $source | Should -Match '\$handler\.UseCookies = \$false'
        $source | Should -Match 'ResponseHeadersRead'
        $source | Should -Match 'ReadAsync\(\$buffer, 0, \$buffer.Length, \$cancellation.Token\)'
        $source | Should -Match '\$buffered.Length \+ \$count -gt \$MaximumBytes'
    }
}

Describe 'Generated utility standalone and module execution' {
    BeforeAll {
        $modulePath = Join-Path $root 'modules/Passkey/Passkey.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
        $cookieScript = Join-Path $root 'scripts/entra/reference/Get-EntraEstsCookieViaTap.ps1'
        $metadataScript = Join-Path $root 'scripts/entra/reference/Get-EntraPasskeyMetadata.ps1'
        $global:PasskeyUtilityArtifactFixture = @{ Requests = [Collections.Generic.List[string]]::new(); State = $null; Mode = '' }
        $syntheticTransport = {
            param($Uri, $MaximumRedirection, $SkipHttpErrorCheck, $ConnectionTimeoutSeconds, $Body, $WebSession)
            $global:PasskeyUtilityArtifactFixture.Requests.Add(([uri]$Uri).AbsolutePath)
            if ($MaximumRedirection -ne 0 -or -not $SkipHttpErrorCheck -or $ConnectionTimeoutSeconds -ne 60) {
                throw 'Generated transport lost its bounded HTTP settings.'
            }
            $requestUri = [uri]$Uri
            if ($requestUri.AbsolutePath.EndsWith('/authorize')) {
                $query = [Web.HttpUtility]::ParseQueryString($requestUri.Query.TrimStart('?'))
                $global:PasskeyUtilityArtifactFixture.State = $query['state']
                if (-not $global:PasskeyUtilityArtifactFixture.State -or $query['code_challenge_method'] -ne 'S256' -or
                    $query['client_id'] -ne '19db86c3-b2b9-44cc-b339-36da233a3be2') { throw 'Synthetic request binding failed.' }
                return [pscustomobject]@{StatusCode=200; Headers=@{};
                    Content='$Config={"pgid":"ConvergedSignIn","sFT":"synthetic-flow","sCtx":"synthetic-context","apiCanary":"synthetic-api-canary","canary":"synthetic-canary","sessionId":"synthetic-session","urlPost":"/common/login"};'}
            }
            if ($requestUri.AbsolutePath -eq '/common/GetCredentialType') {
                return [pscustomobject]@{StatusCode=200; Headers=@{}; Content='{"FlowToken":"synthetic-next-flow"}'}
            }
            if ($requestUri.AbsolutePath -eq '/common/login') {
                $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
                if ($form['accesspass'] -ne 'synthetic-tap' -or $form['loginfmt'] -ne 'user@example.test') { throw 'Synthetic TAP form mismatch.' }
                $WebSession.Cookies.Add([Net.Cookie]::new('ESTSAUTH', 'synthetic-whole-artifact-cookie', '/', '.login.microsoftonline.com'))
                if ($global:PasskeyUtilityArtifactFixture.Mode -eq 'Consent') {
                    return [pscustomobject]@{StatusCode=200; Headers=@{}; Content='$Config={"pgid":"Consent"};'}
                }
                $state = if ($global:PasskeyUtilityArtifactFixture.Mode -eq 'StateMismatch') { 'wrong-state' } else { $global:PasskeyUtilityArtifactFixture.State }
                return [pscustomobject]@{StatusCode=302; Headers=@{Location="https://mysignins.microsoft.com/#code=synthetic-code&state=$state"}; Content=''}
            }
            if ($requestUri.AbsolutePath.EndsWith('/token')) {
                $client = '19db86c3-b2b9-44cc-b339-36da233a3be2'
                $tokenTenant = if ($global:PasskeyUtilityArtifactFixture.Mode -eq 'TenantMismatch') { '22222222-2222-2222-2222-222222222222' } else { '33333333-3333-3333-3333-333333333333' }
                $claims = @{aud=$client; appid=$client; tid=$tokenTenant; upn='user@example.test'; exp=[DateTimeOffset]::UtcNow.AddMinutes(5).ToUnixTimeSeconds()}
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
                return [pscustomobject]@{StatusCode=200; Headers=@{};
                    Content=(@{access_token="e30.$encoded.c2ln"; refresh_token='synthetic-refresh-token'} | ConvertTo-Json -Compress)}
            }
            throw 'No live or unexpected HTTP calls are permitted.'
        }
    }

    AfterAll { Remove-Variable PasskeyUtilityArtifactFixture -Scope Global }

    BeforeEach {
        $global:PasskeyUtilityArtifactFixture.Requests = [Collections.Generic.List[string]]::new()
        $global:PasskeyUtilityArtifactFixture.State = $null
        $global:PasskeyUtilityArtifactFixture.Mode = ''
        Mock Invoke-WebRequest -MockWith $syntheticTransport
        Mock Invoke-WebRequest -ModuleName Passkey -MockWith $syntheticTransport
        Mock Invoke-EntraPasskeyMetadataDownload -ModuleName Passkey { throw 'Live MDS download is forbidden.' }
        Mock Get-EntraPasskeyMetadataGraphData -ModuleName Passkey { throw 'Unrequested Graph reads are forbidden.' }
    }

    It 'executes the actual <Mode> cookie command with only mocked HTTP' -ForEach @(
        @{Mode='Standalone'}, @{Mode='Module'}
    ) {
        $tap = ConvertTo-SecureString 'synthetic-tap' -AsPlainText -Force
        if ($Mode -eq 'Standalone') {
            $result = & $cookieScript -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant
        } else {
            $result = Passkey\Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant
        }
        $result.CookieValue | Should -BeOfType ([Security.SecureString])
        [Net.NetworkCredential]::new('', $result.CookieValue).Password | Should -BeExactly 'synthetic-whole-artifact-cookie'
        $global:PasskeyUtilityArtifactFixture.Requests.Count | Should -Be 4
        $global:PasskeyUtilityArtifactFixture.Requests[3] | Should -Be "/$tenant/oauth2/v2.0/token"
    }

    It 'rejects <Failure> in the actual <Mode> command even when a cookie was set' -ForEach @(
        @{Mode='Standalone'; Failure='StateMismatch'}, @{Mode='Module'; Failure='StateMismatch'},
        @{Mode='Standalone'; Failure='Consent'}, @{Mode='Module'; Failure='Consent'},
        @{Mode='Standalone'; Failure='TenantMismatch'}, @{Mode='Module'; Failure='TenantMismatch'}
    ) {
        $global:PasskeyUtilityArtifactFixture.Mode = $Failure
        $tap = ConvertTo-SecureString 'synthetic-tap' -AsPlainText -Force
        if ($Mode -eq 'Standalone') {
            { & $cookieScript -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw
        } else {
            { Passkey\Get-EntraEstsCookieViaTap -TAP $tap -UserPrincipalName 'user@example.test' -TenantId $tenant } | Should -Throw
        }
        $global:PasskeyUtilityArtifactFixture.Requests.Count | Should -Be $(if ($Failure -eq 'TenantMismatch') {4} else {3})
    }

    It 'executes the actual <Mode> metadata command with explicit fixture data' -ForEach @(
        @{Mode='Standalone'}, @{Mode='Module'}
    ) {
        if ($Mode -eq 'Standalone') {
            $result = & $metadataScript -MdsPayload $fixture -AllowedAaguid $known -RegisteredAaguid $unknown
        } else {
            $result = Passkey\Get-EntraPasskeyMetadata -MdsPayload $fixture -AllowedAaguid $known -RegisteredAaguid $unknown
        }
        $result.MetadataVerified | Should -BeFalse
        $result.MetadataTrustWarning | Should -Match 'unverified'
        $result.AllowedEntries[0].Description | Should -BeExactly 'Synthetic authenticator'
        $result.RegisteredEntries[0].MetadataFound | Should -BeFalse
        $global:PasskeyUtilityArtifactFixture.Requests.Count | Should -Be 0
        Should -Invoke Invoke-EntraPasskeyMetadataDownload -ModuleName Passkey -Times 0 -Exactly
        Should -Invoke Get-EntraPasskeyMetadataGraphData -ModuleName Passkey -Times 0 -Exactly
    }
}
