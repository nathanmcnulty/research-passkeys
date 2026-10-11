BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $manifest = Import-PowerShellDataFile "$repo/build/targets.psd1"
    $global:SoftwareNativeFixture = @{}
}
AfterAll { Remove-Variable SoftwareNativeFixture -Scope Global }
Describe 'Complete native <Flow> software registration through <Surface>' -ForEach @(
    @{ Flow = 'Tap'; Surface = 'Source' }, @{ Flow = 'Ests'; Surface = 'Source' },
    @{ Flow = 'Tap'; Surface = 'Module' }, @{ Flow = 'Ests'; Surface = 'Module' },
    @{ Flow = 'Tap'; Surface = 'Standalone' }, @{ Flow = 'Ests'; Surface = 'Standalone' }
) {
    BeforeEach {
        $name = if ($Flow -eq 'Tap') { 'Register-EntraSoftwarePasskeyViaTap' } else { 'Register-EntraSoftwarePasskeyViaEstsAuth' }
        $targetPath = "powershell/scripts/entra/reference/$name.ps1"
        $sources = ($manifest.Scripts | Where-Object Path -EQ $targetPath).Sources
        $mockScope = @{}
        if ($Surface -eq 'Module') {
            Import-Module "$repo/powershell/modules/Passkey/Passkey.psd1" -Force
            $mockScope.ModuleName = 'Passkey'; $command = "Passkey\$name"
        } elseif ($Surface -eq 'Source') {
            foreach ($source in $sources) { . "$repo/$source" }
            $command = $name
        } else { $command = "$repo/$targetPath" }
        $global:SoftwareNativeFixture.Clear()
        $global:SoftwareNativeFixture.Mode = 'success'; $global:SoftwareNativeFixture.TokenRequests = 0; $global:SoftwareNativeFixture.SessionRequests = 0
        # All requests use the same raw transport. Synthetic JWT claims are consistency fixtures only.
        Mock Invoke-WebRequest {
            $content = ''; $status = 200; $responseHeaders = @{}
            if ($Uri -match '/authorize\?') {
                $global:SoftwareNativeFixture.State = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)['state']
                if ($Flow -eq 'Ests') {
                    @($WebSession.Cookies.GetCookies([uri]'https://login.microsoftonline.com/') | Where-Object Name -In @('ESTSAUTH', 'ESTSAUTHPERSISTENT')).Count | Should -Be 2
                    if ($global:SoftwareNativeFixture.Mode -eq 'consent') { $content = '$Config={"pgid":"Consent"};' }
                    else {
                        $state = if ($global:SoftwareNativeFixture.Mode -eq 'badstate') { 'wrong' } else { $global:SoftwareNativeFixture.State }
                        $status = 302; $responseHeaders.Location = @("https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$state")
                    }
                } else {
                    $content = '$Config={"pgid":"ConvergedSignIn","sFT":"fixture-flow","sCtx":"fixture-context","canary":"fixture-canary","apiCanary":"fixture-api","sessionId":"fixture-session","urlPost":"/common/login"};'
                }
            } elseif ($Uri -match 'GetCredentialType') {
                $content = '{"FlowToken":"fixture-flow"}'
            } elseif ($Uri -match '/common/login$') {
                if ($global:SoftwareNativeFixture.Mode -eq 'consent') {
                    $content = '$Config={"pgid":"Consent"};<form action="/consent"><input type="hidden" name="accept" value="yes"></form>'
                } else {
                    $state = if ($global:SoftwareNativeFixture.Mode -eq 'badstate') { 'wrong-state' } else { $global:SoftwareNativeFixture.State }
                    $status = 302; $responseHeaders.Location = @("https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$state")
                }
            } elseif ($Uri -match '/token$') {
                $global:SoftwareNativeFixture.TokenRequests++
                $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
                $claimsRequest = $form['claims'] | ConvertFrom-Json
                $claimsRequest.access_token.amr.values | Should -Contain ngcmfa
                if ($global:SoftwareNativeFixture.TokenRequests -eq 1) { $form['grant_type'] | Should -Be authorization_code }
                else { $form['grant_type'] | Should -Be refresh_token }
                $claims = @{ aud = '19db86c3-b2b9-44cc-b339-36da233a3be2'; appid = '19db86c3-b2b9-44cc-b339-36da233a3be2'; tid = '11111111-1111-1111-1111-111111111111'; upn = 'fixture@example.invalid'; exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
                if ($global:SoftwareNativeFixture.Mode -eq 'badclient') { $claims.appid = 'wrong' }
                if ($global:SoftwareNativeFixture.Mode -eq 'badtenant') { $claims.tid = '22222222-2222-2222-2222-222222222222' }
                if ($global:SoftwareNativeFixture.Mode -eq 'baduser') { $claims.upn = 'other@example.invalid' }
                $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
                $content = @{ access_token = "e30.$payload.synthetic"; refresh_token = 'SYNTHETIC-REFRESH-TOKEN' } | ConvertTo-Json -Compress
                $Headers.Origin | Should -Be 'https://mysignins.microsoft.com'
            } elseif ($Uri -match '/api/session/authorize$') {
                $global:SoftwareNativeFixture.SessionRequests++
                $content = @{ isAuthorized = $true; sessionCtxV2 = 'SYNTHETIC-SESSION'; requireNgcMfaForSecurityInfo = ($global:SoftwareNativeFixture.SessionRequests -eq 1) } | ConvertTo-Json -Compress
            } elseif ($Uri -match '/authenticationmethods/new$') {
                $data = @{ requestData = @{ canary = 'fixture-canary'; serverChallenge = 'AQIDBA'; userId = 'BQYHCA'; postBackUrl = 'https://mysignins.microsoft.com/api/post/newfido' }; provisionUrl = 'https://login.microsoft.com/tenant/fido/create' } | ConvertTo-Json -Depth 5 -Compress
                $content = @{ ErrorCode = 0; Data = $data } | ConvertTo-Json -Compress
            } elseif ($Uri -match '/fido/create\?') {
                if ($global:SoftwareNativeFixture.Mode -eq 'createfail') { $status = 400 }
                $content = 'fixture-created'
            } elseif ($Uri -match '/post/newfido\?') {
                $fields = [Web.HttpUtility]::ParseQueryString([string]$Body)
                $global:SoftwareNativeFixture.CredentialId = $fields['credentialId']
                $content = '<div id="context" data-content="{&quot;Canary&quot;:&quot;fixture-canary&quot;,&quot;PostInfo&quot;:&quot;fixture-post&quot;}"></div>'
            } elseif ($Uri -match '/authenticationmethods(/availablemethods)?$') {
                $content = '{}'
            } elseif ($Uri -match '/authenticationmethods/verify$') {
                $verification = ($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json
                $id = $verification.CredentialId
                $id | Should -BeExactly $global:SoftwareNativeFixture.CredentialId
                if ($global:SoftwareNativeFixture.Mode -eq 'mismatch') { $id = 'wrong-credential' }
                $errorCode = if ($global:SoftwareNativeFixture.Mode -eq 'protocolerror') { 1 } else { 0 }
                $status = if ($global:SoftwareNativeFixture.Mode -eq 'httperror') { 400 } else { 200 }
                $content = @{ VerificationState = 2; ErrorCode = $errorCode; DataUpdates = @{ FidoDevices = @{ CredentialId = $id } } } | ConvertTo-Json -Depth 6 -Compress
            } else { throw "Unexpected mocked request path $(([uri]$Uri).AbsolutePath)." }
            return @{ StatusCode = $status; Content = $content; Headers = $responseHeaders }
        } @mockScope
        Mock Invoke-RestMethod { throw 'All native registration requests must use the bounded raw transport.' } @mockScope
        $outputPath = Join-Path $TestDrive "$Flow-$Surface-$([guid]::NewGuid().ToString('N')).json"
        $parameters = @{ TenantId = '11111111-1111-1111-1111-111111111111'; OutputPath = $outputPath; Confirm = $false }
        if ($Flow -eq 'Tap') {
            $parameters.TAP = ConvertTo-SecureString 'SYNTHETIC-TAP' -AsPlainText -Force
            $parameters.UserPrincipalName = 'fixture@example.invalid'
            $parameters.DisplayName = 'Native fixture'
        } else {
            $parameters.ESTSAuthCookie = ConvertTo-SecureString 'SYNTHETIC-COOKIE' -AsPlainText -Force
            $parameters.PasskeyDisplayName = 'Native fixture'
        }
    }
    It 'verifies the expected credential before persisting its matching software key' {
        (Get-Command $command).Parameters.Keys | Should -Not -Contain 'AllowLegacySoftwareAttestation'
        $warnings = @()
        $result = & $command @parameters -WarningVariable warnings
        @($warnings).Count | Should -Be 1
        [string]$warnings[0] | Should -Match 'not a FIDO-certified authenticator.*UP/UV flags are synthetic'
        $result.Success | Should -BeTrue
        $saved = Get-Content $outputPath -Raw | ConvertFrom-Json
        $saved.credentialId | Should -BeExactly $global:SoftwareNativeFixture.CredentialId
        $saved.privateKey | Should -Match '^-----BEGIN PRIVATE KEY-----'
        $saved.displayName | Should -Be 'Native fixture'
        $saved.userName | Should -Be 'fixture@example.invalid'
        $result | ConvertTo-Json -Depth 5 | Should -Not -Match 'BEGIN PRIVATE|SYNTHETIC'
        $global:SoftwareNativeFixture.TokenRequests | Should -Be 2
    }
    It 'cleans the output reservation after state client consent create or verification failure' -ForEach @('badstate', 'badclient', 'consent', 'createfail', 'mismatch') {
        $global:SoftwareNativeFixture.Mode = $_
        { & $command @parameters } | Should -Throw
        Test-Path $outputPath | Should -BeFalse
    }
    It 'performs no auth network key generation or output writes under WhatIf' {
        & $command @parameters -WhatIf
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly @mockScope
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly @mockScope
        Test-Path $outputPath | Should -BeFalse
    }
}
