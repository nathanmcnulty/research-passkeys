BeforeAll {
    $oldCalls = $env:PASSKEY_TEST_CALLS
    $oldMode = $env:PASSKEY_TEST_CLI_MODE
    $root = Split-Path $PSScriptRoot -Parent
    $registration = "$root/Register-GitHubPasskeyViaTAP.ps1"
    $repo = Split-Path (Split-Path $root -Parent) -Parent
    $manifest = Import-PowerShellDataFile "$repo/build/targets.psd1"
    $registrationSources = ($manifest.Scripts | Where-Object Path -EQ 'github/adapters/Register-GitHubPasskeyViaTAP.ps1').Sources
    . (Join-Path $PSScriptRoot 'fixtures/New-FakeGitHubCli.ps1')
    $ghCalls = Join-Path $TestDrive 'gh-calls.txt'
    $fakeGh = New-FakeGitHubCli -Directory (Join-Path $TestDrive 'native-gh')
    $env:PASSKEY_TEST_CALLS = $ghCalls
    $env:PASSKEY_TEST_CLI_MODE = 'record'
    $global:PasskeyOfflineFixture = @{}
}
AfterAll {
    $env:PASSKEY_TEST_CALLS = $oldCalls
    $env:PASSKEY_TEST_CLI_MODE = $oldMode
    Remove-Variable PasskeyOfflineFixture -Scope Global -ErrorAction SilentlyContinue
}
Describe 'Complete TAP registration transcript through <Surface>' -ForEach @(@{ Surface = 'Source' }, @{ Surface = 'Module' }, @{ Surface = 'Standalone' }) {
    BeforeEach {
        $mockScope = @{}
        if ($Surface -eq 'Module') {
            Import-Module "$repo/powershell/modules/Passkey/Passkey.psd1" -Force
            $mockScope.ModuleName = 'Passkey'
            $registrationCommand = 'Passkey\Register-GitHubPasskeyViaTAP'
        } elseif ($Surface -eq 'Source') {
            foreach ($source in $registrationSources) { . "$repo/$source" }
            $registrationCommand = 'Register-GitHubPasskeyViaTAP'
        } else { $registrationCommand = $registration }
        Remove-Item $ghCalls -ErrorAction SilentlyContinue
        $global:PasskeyOfflineFixture.Clear()
        $global:PasskeyOfflineFixture.Mode = 'success'
        $global:PasskeyOfflineFixture.TokenRequests = 0
        $global:PasskeyOfflineFixture.SessionRequests = 0
        Mock Get-Command { [pscustomobject]@{ Source = $fakeGh } } -ParameterFilter { $Name -eq 'gh' } @mockScope
        # All requests use the same raw transport. Synthetic JWT claims are consistency fixtures only.
        Mock Invoke-WebRequest {
            $content = ''; $status = 200; $responseHeaders = @{}
            if ($Uri -match '/authorize\?') {
                $global:PasskeyOfflineFixture.State = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)['state']
                $content = '$Config={"pgid":"ConvergedSignIn","sFT":"fixture-flow","sCtx":"fixture-context","canary":"fixture-canary","apiCanary":"fixture-api","sessionId":"fixture-session","urlPost":"/common/login"};'
            } elseif ($Uri -match 'GetCredentialType') {
                $content = '{"FlowToken":"fixture-flow"}'
            } elseif ($Uri -match '/common/login$') {
                if ($global:PasskeyOfflineFixture.Mode -eq 'consent') {
                    $content = '$Config={"pgid":"Consent"};<form action="/consent"><input type="hidden" name="accept" value="yes"></form>'
                } else {
                    $state = if ($global:PasskeyOfflineFixture.Mode -eq 'badstate') { 'wrong-state' } else { $global:PasskeyOfflineFixture.State }
                    $status = 302; $responseHeaders.Location = @("https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$state")
                }
            } elseif ($Uri -match '/token$') {
                $global:PasskeyOfflineFixture.TokenRequests++
                $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
                $claimsRequest = $form['claims'] | ConvertFrom-Json
                $claimsRequest.access_token.amr.values | Should -Contain ngcmfa
                if ($global:PasskeyOfflineFixture.TokenRequests -eq 1) { $form['grant_type'] | Should -Be authorization_code }
                else { $form['grant_type'] | Should -Be refresh_token }
                $claims = @{ aud = '19db86c3-b2b9-44cc-b339-36da233a3be2'; appid = '19db86c3-b2b9-44cc-b339-36da233a3be2'; tid = '11111111-1111-1111-1111-111111111111'; upn = 'fixture@example.invalid'; exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
                if ($global:PasskeyOfflineFixture.Mode -eq 'badclient') { $claims.appid = 'wrong' }
                if ($global:PasskeyOfflineFixture.Mode -eq 'badtenant') { $claims.tid = '22222222-2222-2222-2222-222222222222' }
                if ($global:PasskeyOfflineFixture.Mode -eq 'baduser') { $claims.upn = 'other@example.invalid' }
                $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
                $content = @{ access_token = "e30.$payload.synthetic"; refresh_token = 'SYNTHETIC-REFRESH-TOKEN' } | ConvertTo-Json -Compress
                $Headers.Origin | Should -Be 'https://mysignins.microsoft.com'
            } elseif ($Uri -match '/api/session/authorize$') {
                $global:PasskeyOfflineFixture.SessionRequests++
                $content = @{ isAuthorized = $true; sessionCtxV2 = 'SYNTHETIC-SESSION'; requireNgcMfaForSecurityInfo = ($global:PasskeyOfflineFixture.SessionRequests -eq 1) } | ConvertTo-Json -Compress
            } elseif ($Uri -match '/authenticationmethods/new$') {
                $data = @{ requestData = @{ canary = 'fixture-canary'; serverChallenge = 'AQIDBA'; userId = 'BQYHCA'; postBackUrl = 'https://mysignins.microsoft.com/api/post/newfido' }; provisionUrl = 'https://login.microsoft.com/tenant/fido/create' } | ConvertTo-Json -Depth 5 -Compress
                $content = @{ ErrorCode = 0; Data = $data } | ConvertTo-Json -Compress
            } elseif ($Uri -match '/fido/create\?') {
                if ($global:PasskeyOfflineFixture.Mode -eq 'createfail') { $status = 400 }
                $content = 'fixture-created'
            } elseif ($Uri -match '/post/newfido\?') {
                $fields = [Web.HttpUtility]::ParseQueryString([string]$Body)
                $global:PasskeyOfflineFixture.CredentialId = $fields['credentialId']
                $content = '<div id="context" data-content="{&quot;Canary&quot;:&quot;fixture-canary&quot;,&quot;PostInfo&quot;:&quot;fixture-post&quot;}"></div>'
            } elseif ($Uri -match '/authenticationmethods(/availablemethods)?$') {
                $content = '{}'
            } elseif ($Uri -match '/authenticationmethods/verify$') {
                $verification = ($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json
                $id = $verification.CredentialId
                $id | Should -BeExactly $global:PasskeyOfflineFixture.CredentialId
                if ($global:PasskeyOfflineFixture.Mode -eq 'mismatch') { $id = 'wrong-credential' }
                $errorCode = if ($global:PasskeyOfflineFixture.Mode -eq 'protocolerror') { 1 } else { 0 }
                $status = if ($global:PasskeyOfflineFixture.Mode -eq 'httperror') { 400 } else { 200 }
                $content = @{ VerificationState = 2; ErrorCode = $errorCode; DataUpdates = @{ FidoDevices = @{ CredentialId = $id } } } | ConvertTo-Json -Depth 6 -Compress
            } else { throw "Unexpected mocked request path $(([uri]$Uri).AbsolutePath)." }
            return @{ StatusCode = $status; Content = $content; Headers = $responseHeaders }
        } @mockScope
        Mock Invoke-RestMethod { throw 'All native registration requests must use the bounded raw transport.' } @mockScope
        $params = @{ TAP = (ConvertTo-SecureString 'SYNTHETIC-TAP' -AsPlainText -Force); UserPrincipalName = 'fixture@example.invalid'; TenantId = '11111111-1111-1111-1111-111111111111'; Repository = 'fixture-owner/fixture-repo'; ConsumersPaused = $true; Confirm = $false }
    }
    It 'completes the synthetic ceremony and writes exactly four names without credentials in outputs' {
        $warnings = @()
        $result = & $registrationCommand @params -WarningVariable warnings
        @($warnings).Count | Should -Be 1
        $result.Success | Should -BeTrue
        $result | ConvertTo-Json -Depth 5 | Should -Not -Match 'SYNTHETIC|BEGIN PRIVATE|fixture@'
        $calls = Get-Content $ghCalls
        @($calls | Where-Object { $_ -match '^secret set ' }).Count | Should -Be 4
        $calls[-1] | Should -Be 'secret set PASSKEY_PRIVATE_KEY --repo github.com/fixture-owner/fixture-repo --app actions'
        $calls -join ' ' | Should -Not -Match 'SYNTHETIC|BEGIN PRIVATE|fixture@'
        $global:PasskeyOfflineFixture.TokenRequests | Should -Be 2
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly @mockScope
    }
    It 'rejects invalid response without any secret write' -ForEach @('badstate','consent','badclient','badtenant','baduser','createfail','mismatch','protocolerror','httperror') {
        $global:PasskeyOfflineFixture.Mode = $_
        { & $registrationCommand @params } | Should -Throw
        # Both read-only preflight invocations reached the real platform-native fixture.
        $calls = @(Get-Content $ghCalls -ErrorAction Stop)
        $calls.Count | Should -Be 2
        $calls[0] | Should -Be 'auth status --hostname github.com'
        @($calls | Where-Object { $_ -match '^secret set ' }).Count | Should -Be 0
        if ($_ -in @('badstate','consent')) { $global:PasskeyOfflineFixture.TokenRequests | Should -Be 0 }
    }
}
