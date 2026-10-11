BeforeAll {
    $script:Repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:Sources = @(
        'Common/Encoding.ps1', 'Common/Values.ps1', 'Common/Cbor.ps1', 'KeyVault/Reference.ps1', 'KeyVault/ProvisioningKeys.ps1',
        'Local/RegistrationKey.ps1', 'Entra/SoftwareBrowserHeaders.ps1', 'Entra/SoftwareSession.ps1', 'Entra/SoftwareAuthorization.ps1', 'Entra/SoftwareAuthentication.ps1',
        'Entra/SoftwareAttestation.ps1', 'Entra/SoftwareCredential.ps1', 'Entra/SoftwareNativeRegistration.ps1', 'Entra/SoftwareOutput.ps1', 'Entra/SoftwareGraphAuthentication.ps1',
        'Entra/SoftwareGraphRegistration.ps1', 'Entra/SoftwareConfiguration.ps1',
        'Entra/KeyVaultRegistrationState.ps1', 'Entra/KeyVaultRegistrationRequests.ps1', 'Entra/KeyVaultRegistrationVerification.ps1',
        'GitHub/SecretValues.ps1', 'GitHub/Transport.ps1', 'Public/ExportGitHubSecret.ps1', 'Public/RegisterGitHubPasskey.ps1',
        'Public/RegisterSoftwarePasskey.ps1', 'Public/RegisterSoftwarePasskeyViaTap.ps1', 'Public/RegisterSoftwarePasskeyViaEstsAuth.ps1'
    )
    foreach ($source in $script:Sources) { . "$script:Repo/powershell/src/$source" }
    $script:OpenOutputImplementation = ${function:Open-EntraSoftwareCredentialOutput}
    $script:Tenant = '11111111-1111-4111-8111-111111111111'
    $script:Client = '19db86c3-b2b9-44cc-b339-36da233a3be2'
    $script:Tap = ConvertTo-SecureString 'synthetic-tap-only' -AsPlainText -Force
    $script:Key = New-SoftwarePasskeyKey
    $script:Credential = [ordered]@{ credentialId = 'AQID'; userHandle = 'BAUG'; userName = 'test@example.test'; privateKey = $script:Key.PrivateKeyPem }
    function New-SyntheticToken {
        param([hashtable]$Override = @{})
        $claims = @{ aud = $script:Client; tid = $script:Tenant; upn = 'test@example.test'; appid = $script:Client; exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
        foreach ($name in $Override.Keys) { $claims[$name] = $Override[$name] }
        'e30.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress)))) + '.synthetic'
    }
}
AfterAll { Clear-SoftwarePasskeyKey $script:Key }

Describe 'Software source architecture' {
    It 'keeps maintained source files functions-only' {
        foreach ($source in $script:Sources) {
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile("$script:Repo/powershell/src/$source", [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            foreach ($statement in $ast.EndBlock.Statements) { $statement | Should -BeOfType ([Management.Automation.Language.FunctionDefinitionAst]) }
        }
    }
    It 'loads all registration sources without network or external CLI' {
        Mock Invoke-RestMethod { throw 'network forbidden' }
        Mock Invoke-WebRequest { throw 'network forbidden' }
        Mock Invoke-GitHubPasskeyCli { throw 'CLI forbidden' }
        foreach ($source in $script:Sources) { . "$script:Repo/powershell/src/$source" }
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
}

Describe 'Bounded registration authorization and binding' {
    It 'accepts only the exact state and approved callback origin' {
        Get-EntraRegistrationAuthorizationCode -Callback 'https://mysignins.microsoft.com/#code=synthetic&state=expected' -ExpectedState expected | Should -Be synthetic
    }
    It 'rejects wrong, missing, duplicate state and authorization errors' -ForEach @(
        @{ Callback = 'https://mysignins.microsoft.com/#code=x&state=wrong' },
        @{ Callback = 'https://mysignins.microsoft.com/#code=x' },
        @{ Callback = 'https://mysignins.microsoft.com/?state=expected#code=x&state=expected' },
        @{ Callback = 'https://mysignins.microsoft.com/#code=x&state=expected&error=denied' },
        @{ Callback = 'https://mysignins.microsoft.com.evil.test/#code=x&state=expected' },
        @{ Callback = 'https://mysignins.microsoft.com/other#code=x&state=expected' },
        @{ Callback = 'https://mysignins.microsoft.com/#code=x&code=y&state=expected' }
    ) {
        { Get-EntraRegistrationAuthorizationCode -Callback $Callback -ExpectedState expected } | Should -Throw
    }
    It 'never submits consent or arbitrary auto-submit forms' {
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{ StatusCode = 200; Content = '$Config={"pgid":"ConvergedConsent"};<form action="/consent"><input type="hidden" name="accept" value="yes"></form>'; Headers = @{} } }
        { Invoke-EntraRegistrationAuthorization -Context (New-EntraRegistrationContext) -Uri 'https://login.microsoftonline.com/common/authorize' } | Should -Throw '*consent*'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
    It 'binds the returned token to client tenant user and expiry' {
        $identity = Assert-EntraRegistrationTokenBinding -Token (New-SyntheticToken) -ClientId $script:Client -TenantId $script:Tenant -UserPrincipalName 'test@example.test'
        $identity.TenantId | Should -Be $script:Tenant
    }
    It 'rejects token audience client tenant user and expiry mismatches' -ForEach @(
        @{ Claims = @{ aud = 'wrong' } }, @{ Claims = @{ appid = 'wrong' } },
        @{ Claims = @{ tid = '22222222-2222-4222-8222-222222222222' } },
        @{ Claims = @{ upn = 'other@example.test' } }, @{ Claims = @{ exp = 1 } }
    ) {
        { Assert-EntraRegistrationTokenBinding -Token (New-SyntheticToken $Claims) -ClientId $script:Client -TenantId $script:Tenant -UserPrincipalName 'test@example.test' } | Should -Throw
    }
    It 'stops a redirect cycle at the configured bound' {
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{ StatusCode = 302; Headers = @{ Location = '/common/authorize' }; Content = '' } }
        { Invoke-EntraRegistrationAuthorization -Context (New-EntraRegistrationContext) -Uri 'https://login.microsoftonline.com/common/authorize' } | Should -Throw '*redirect limit*'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 15 -Exactly
    }
    It 'rejects cross-origin TAP body redirects' {
        Mock Invoke-EntraRegistrationWebRequest { [pscustomobject]@{ StatusCode = 307; Headers = @{ Location = 'https://login.microsoft.com/submit' }; Content = '' } }
        { Invoke-EntraRegistrationAuthorization -Context (New-EntraRegistrationContext) -Uri 'https://login.microsoftonline.com/common/login' -Method POST -Body 'synthetic' } | Should -Throw '*Cross-origin*'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
}

Describe 'Software attestation and provider lifecycle' {
    It 'keeps Graph attestation none without packed legacy consent' {
        $attestation = New-EntraSoftwareAttestation -Provider $script:Key -Challenge AQID
        $encoded = ConvertFrom-Base64Url $attestation.AttestationObject
        [Text.Encoding]::Latin1.GetString($encoded) | Should -Match 'none'
        $client = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $attestation.ClientDataJson)) | ConvertFrom-Json
        $client.challenge | Should -Be AQID
        $client.origin | Should -Be 'https://login.microsoft.com'
    }
    It 'requires explicit acknowledgement for packed software attestation' {
        { New-EntraSoftwareAttestation -Provider $script:Key -Challenge synthetic -Format LegacyPacked } | Should -Throw '*AllowLegacySoftwareAttestation*'
    }
    It 'encodes native JWE challenge bytes and preserves synthetic claims as research' {
        $attestation = New-EntraSoftwareAttestation -Provider $script:Key -Challenge synthetic -Format LegacyPacked -AllowLegacySoftwareAttestation
        $client = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $attestation.ClientDataJson)) | ConvertFrom-Json
        $client.challenge | Should -Be (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('synthetic')))
        $data = New-EntraSoftwareAuthenticatorData -RpId 'login.microsoft.com' -CredentialId ([byte[]]::new(32)) -PublicX $script:Key.PublicX -PublicY $script:Key.PublicY
        $data[32] | Should -Be 0x45
    }
    It 'disposes the key and clears the export representation' {
        $provider = New-SoftwarePasskeyKey
        Clear-SoftwarePasskeyKey $provider
        $provider.Key | Should -BeNullOrEmpty
        $provider.PrivateKeyPem | Should -BeNullOrEmpty
    }
}

Describe 'Software public WhatIf and persistence' {
    BeforeEach {
        Mock New-SoftwarePasskeyKey { throw 'must not generate a key' }
        Mock New-EntraRegistrationContext { throw 'must not create a session' }
        Mock Open-EntraSoftwareCredentialOutput { throw 'must not write a file' }
        Mock Invoke-EntraSoftwareGraphRegistration { throw 'must not register' }
        Mock Invoke-EntraSoftwareNativeRegistration { throw 'must not register' }
        Mock Test-GitHubPasskeyDestination { throw 'must not invoke CLI' }
    }
    It 'performs no I/O for Graph WhatIf' {
        Register-EntraSoftwarePasskey -UserUpn 'test@example.test' -UseManagedIdentity -WhatIf
        Should -Invoke New-SoftwarePasskeyKey -Times 0 -Exactly
        Should -Invoke Open-EntraSoftwareCredentialOutput -Times 0 -Exactly
        Should -Invoke Invoke-EntraSoftwareGraphRegistration -Times 0 -Exactly
    }
    It 'performs no I/O for TAP ESTS and GitHub WhatIf' {
        Register-EntraSoftwarePasskeyViaTap -TAP $script:Tap -UserPrincipalName 'test@example.test' -TenantId $script:Tenant -AllowLegacySoftwareAttestation -WhatIf
        Register-EntraSoftwarePasskeyViaEstsAuth -ESTSAuthCookie $script:Tap -AllowLegacySoftwareAttestation -WhatIf
        Register-GitHubPasskeyViaTAP -TAP $script:Tap -UserPrincipalName 'test@example.test' -TenantId $script:Tenant -Repository 'owner/repo' -ConsumersPaused -AllowLegacySoftwareAttestation -WhatIf
        Should -Invoke New-EntraRegistrationContext -Times 0 -Exactly
        Should -Invoke Open-EntraSoftwareCredentialOutput -Times 0 -Exactly
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 0 -Exactly
        Should -Invoke Test-GitHubPasskeyDestination -Times 0 -Exactly
    }
    It 'does not overwrite a previously saved credential' {
        $file = Join-Path $TestDrive 'existing.json'
        [IO.File]::WriteAllText($file, 'retained')
        { & $script:OpenOutputImplementation $file } | Should -Throw
        [IO.File]::ReadAllText($file) | Should -Be retained
    }
}

Describe 'GitHub whole-record and partial-write safeguards' {
    BeforeEach { Mock Test-GitHubPasskeyDestination {} }
    It 'keeps the four exact secret names and private key last' {
        $values = Get-GitHubPasskeySecretValues $script:Credential
        ($values.Keys -join ',') | Should -Be 'PASSKEY_PRIVATE_CREDENTIAL_ID,PASSKEY_PRIVATE_USER_HANDLE,PASSKEY_PRIVATE_USER_PRINCIPAL_NAME,PASSKEY_PRIVATE_KEY'
    }
    It 'requires paused consumers even for valid credentials' {
        { Export-PasskeyToGitHubSecret -Credential $script:Credential -Repository owner/repo -Confirm:$false } | Should -Throw '*ConsumersPaused*'
    }
    It 'validates the complete record before invoking CLI' {
        Mock Invoke-GitHubPasskeyCli { throw 'unexpected' }
        $bad = [ordered]@{} + $script:Credential
        $bad.userHandle = 'noncanonical+'
        { Export-PasskeyToGitHubSecret -Credential $bad -Repository owner/repo -ConsumersPaused -Confirm:$false } | Should -Throw
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'performs no I/O on exporter WhatIf' {
        Mock Invoke-GitHubPasskeyCli { throw 'unexpected' }
        Export-PasskeyToGitHubSecret -Credential $script:Credential -Repository owner/repo -ConsumersPaused -WhatIf
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
        Should -Invoke Test-GitHubPasskeyDestination -Times 0 -Exactly
    }
    It 'halts on each failed/uncertain write without leaking values or rolling back' -ForEach @(@{ Position = 1 }, @{ Position = 2 }, @{ Position = 3 }, @{ Position = 4 }) {
        $script:Calls = 0
        Mock Invoke-GitHubPasskeyCli {
            $script:Calls++
            if ($script:Calls -eq $Position) { throw 'raw synthetic private data should be suppressed' }
            $Arguments | Should -Not -Contain $script:Credential.privateKey
            $Arguments | Should -Not -Contain '--body'
        }
        $failure = $null
        try { Export-PasskeyToGitHubSecret -Credential $script:Credential -Repository owner/repo -ConsumersPaused -Confirm:$false } catch { $failure = $_.Exception.Message }
        $failure | Should -Match 'Keep consumers paused'
        $failure | Should -Not -Match 'raw synthetic'
        $failure | Should -Match 'No rollback'
        Should -Invoke Invoke-GitHubPasskeyCli -Times $Position -Exactly
    }
    It 'does not export or claim success after unverified enrollment' {
        Mock New-EntraRegistrationContext { [pscustomobject]@{ Token = $null; RefreshToken = $null; CodeVerifier = $null; SessionCtxV2 = $null; WebSession = $null } }
        Mock Invoke-EntraRegistrationTapAuthentication { $Context }
        Mock Invoke-EntraSoftwareNativeRegistration { throw 'verification did not bind expected ID' }
        Mock Export-PasskeyToGitHubSecret { throw 'must not export' }
        { Register-GitHubPasskeyViaTAP -TAP $script:Tap -UserPrincipalName 'test@example.test' -TenantId $script:Tenant -Repository owner/repo -ConsumersPaused -AllowLegacySoftwareAttestation -Confirm:$false } | Should -Throw '*partially enrolled*'
        Should -Invoke Export-PasskeyToGitHubSecret -Times 0 -Exactly
    }
    It 'preserves export failure as post-enrollment failure' {
        Mock New-EntraRegistrationContext { [pscustomobject]@{ Token = $null; RefreshToken = $null; CodeVerifier = $null; SessionCtxV2 = $null; WebSession = $null } }
        Mock Invoke-EntraRegistrationTapAuthentication { $Context }
        Mock Invoke-EntraSoftwareNativeRegistration { [pscustomobject]@{ Credential = [ordered]@{ privateKey = 'synthetic' } } }
        Mock Export-PasskeyToGitHubSecret { throw 'GitHub export incomplete. Keep consumers paused. No rollback was attempted.' }
        { Register-GitHubPasskeyViaTAP -TAP $script:Tap -UserPrincipalName 'test@example.test' -TenantId $script:Tenant -Repository owner/repo -ConsumersPaused -AllowLegacySoftwareAttestation -Confirm:$false } | Should -Throw '*Enrollment completed, but export did not finish*'
    }
}

Describe 'Graph and native authentication transport details' {
    It 'pins redirects and bounds connection and response streaming without mutating caller headers' {
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{}'; Headers = @{} } }
        $headers = @{ Origin = 'https://mysignins.microsoft.com' }
        $null = Invoke-EntraRegistrationWebRequest -Uri 'https://mysignins.microsoft.com/api/session/authorize' -Headers $headers
        $headers.ContainsKey('User-Agent') | Should -BeFalse
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $MaximumRedirection -eq 0 -and $ConnectionTimeoutSeconds -eq 60 -and $OperationTimeoutSeconds -eq 60 -and
            $SkipHttpErrorCheck -and $Headers['Accept'] -eq '*/*'
        }
    }
    It 'discovers a concrete tenant through v2 metadata rather than a v1 userinfo URL' {
        Mock Invoke-EntraRegistrationRestMethod { @{ issuer = "https://login.microsoftonline.com/$script:Tenant/v2.0" } }
        Resolve-EntraSoftwareGraphTenant -UserUpn 'test@example.test' | Should -Be $script:Tenant
        Should -Invoke Invoke-EntraRegistrationRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://login.microsoftonline.com/example.test/v2.0/.well-known/openid-configuration' }
    }
    It 'rejects a discovery issuer with an unrelated origin' {
        Mock Invoke-EntraRegistrationRestMethod { @{ issuer = "https://mysignins.microsoft.com/$script:Tenant/v2.0" } }
        { Resolve-EntraSoftwareGraphTenant -UserUpn 'test@example.test' } | Should -Throw '*issuer*'
    }
    It 'creates a verifiable synthetic RSA client certificate assertion with base64url thumbprint' {
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $certificate = $null
        $loaded = $null
        $verifier = $null
        try {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Synthetic Only', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
            $path = Join-Path $TestDrive 'synthetic.pfx'
            [IO.File]::WriteAllBytes($path, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'synthetic'))
            $tokenUri = "https://login.microsoftonline.com/$script:Tenant/oauth2/v2.0/token"
            $jwt = New-EntraSoftwareCertificateAssertion -TokenUri $tokenUri -ClientId $script:Client -CertificatePath $path -CertificatePassword (ConvertTo-SecureString synthetic -AsPlainText -Force)
            $parts = $jwt.Split('.')
            $header = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[0])) | ConvertFrom-Json
            $payload = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json
            $header.x5t | Should -Be (ConvertTo-Base64Url ($certificate.GetCertHash()))
            $payload.aud | Should -Be $tokenUri
            $payload.exp - $payload.nbf | Should -Be 600
            $verifier = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
            $verifier.VerifyData([Text.Encoding]::UTF8.GetBytes($parts[0]+'.'+$parts[1]), (ConvertFrom-Base64Url $parts[2]), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1) | Should -BeTrue
        } finally { if ($verifier) { $verifier.Dispose() }; if ($certificate) { $certificate.Dispose() }; $rsa.Dispose() }
    }
}
