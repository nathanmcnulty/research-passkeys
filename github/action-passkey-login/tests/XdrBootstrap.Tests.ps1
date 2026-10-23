# Synthetic portal fixtures only. Never send a real cookie or contact Microsoft.
BeforeAll {
    $script:helper = Join-Path $PSScriptRoot '../scripts/Test-XdrConnectionByEstsCookie.ps1'
    $script:workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/test-xdr-key-vault.yml') -Raw
}
Describe 'XDR portal bootstrap evidence boundary' {
    BeforeEach {
        $global:XdrBootstrapFixture = @{}
        $global:XdrBootstrapFixture.addPortalCookie = $true
        $global:XdrBootstrapFixture.missingField = $false
        $global:XdrBootstrapFixture.postFailure = $false
        $global:XdrBootstrapFixture.postStatus = 200
        $global:XdrBootstrapFixture.postShape = 'single'
        $global:XdrBootstrapFixture.cookieName = 'anonymous-tracking'
        Mock Invoke-RestMethod { throw 'Unexpected REST request in offline fixture.' }
        Mock Invoke-WebRequest {
            if ($Uri -eq 'https://login.microsoftonline.com/error') { return @{Content='';InputFields=@()} }
            if ($Uri -ne 'https://security.microsoft.com/') { throw 'Unexpected fixture destination.' }
            if ($Method -eq 'Get') {
                if ($global:XdrBootstrapFixture.addPortalCookie) {
                    $cookie = [Net.Cookie]::new($global:XdrBootstrapFixture.cookieName,'SYNTHETIC','/','security.microsoft.com')
                    $cookie.Secure = $true
                    $WebSession.Cookies.Add($cookie)
                }
                $fields = @('code','id_token','state','session_state','correlation_id')
                if ($global:XdrBootstrapFixture.missingField) { $fields = @('code','id_token','state','session_state') }
                return @{InputFields=@($fields | ForEach-Object { [pscustomobject]@{name=$_;value='SYNTHETIC'} });Content=''}
            }
            if ($Method -eq 'Post') {
                if ($global:XdrBootstrapFixture.postFailure) { throw 'SYNTHETIC-SECRET-SERVICE-ERROR' }
                if ($global:XdrBootstrapFixture.postShape -eq 'null') { return $null }
                if ($global:XdrBootstrapFixture.postShape -eq 'multiple') { return @(@{StatusCode=200},@{StatusCode=200}) }
                return @{Content='';InputFields=@();StatusCode=$global:XdrBootstrapFixture.postStatus}
            }
            throw 'Unexpected fixture method.'
        }
    }
    AfterEach { Remove-Variable XdrBootstrapFixture -Scope Global -ErrorAction SilentlyContinue }
    It 'reports only bootstrap evidence even when portal cookies exist: <Name>' -ForEach @(
        @{Name='anonymous-tracking'}, @{Name='apparently-authenticated-cookie'}
    ) {
        $global:XdrBootstrapFixture.cookieName = $Name
        $result = & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS'
        $result.BootstrapCompleted | Should -BeTrue
        $result.ValidationScope | Should -BeExactly 'PortalBootstrapOnly'
        $result.AuthenticationVerified | Should -BeFalse
        $result.Success | Should -BeFalse
        $result.XdrCookieNames | Should -Contain $Name
        ($result | ConvertTo-Json) | Should -Not -Match 'SYNTHETIC'
        Should -Invoke Invoke-WebRequest -Times 3 -Exactly
        Should -Invoke Invoke-RestMethod -Times 0
    }
    It 'rejects failed form exchange even when GET already set a portal cookie' {
        $global:XdrBootstrapFixture.postFailure = $true
        $caught = $null
        try { & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS' } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeExactly 'XDR portal bootstrap form exchange failed; authenticated access remains unverified.'
        $caught.Exception.Message | Should -Not -Match 'SYNTHETIC'
    }
    It 'rejects non-success HTTP status even with a portal cookie: <_>' -ForEach @(400,500,302) {
        $global:XdrBootstrapFixture.postStatus = $_
        { & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS' } | Should -Throw '*form exchange failed*'
    }
    It 'rejects absent or ambiguous form responses despite existing cookies: <_>' -ForEach @('null','multiple') {
        $global:XdrBootstrapFixture.postShape = $_
        { & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS' } | Should -Throw '*form exchange failed*'
    }
    It 'fails without a portal cookie instead of declaring bootstrap complete' {
        $global:XdrBootstrapFixture.addPortalCookie = $false
        { & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS' } | Should -Throw '*cookies were not established*'
    }
    It 'fails incomplete form evidence before submitting the portal form' {
        $global:XdrBootstrapFixture.missingField = $true
        { & $script:helper -EstsCookieValue 'SYNTHETIC-ESTS' } | Should -Throw '*correlation_id*missing*'
        Should -Invoke Invoke-WebRequest -Times 0 -ParameterFilter { $Method -eq 'Post' }
    }
    It 'keeps the workflow manual and explicitly scoped to bootstrap rather than authenticated readback' {
        $script:workflow | Should -Match 'workflow_dispatch:'
        $script:workflow | Should -Not -Match '(?m)^\s*(push|pull_request|pull_request_target|schedule):'
        $script:workflow | Should -Not -Match '(?m)^          (if|Write-Host).*\$\{\{'
        $script:workflow | Should -Match 'PortalBootstrapOnly'
        $script:workflow | Should -Match 'Authenticated XDR readback remains unverified'
        $script:workflow | Should -Not -Match 'XDR validation succeeded|Expected the XDR validation script to return Success = true'
    }
}
