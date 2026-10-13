BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    foreach ($source in @(
        'powershell/src/Common/Encoding.ps1', 'powershell/src/Common/Cbor.ps1', 'powershell/src/Common/Values.ps1',
        'powershell/src/KeyVault/Reference.ps1', 'powershell/src/KeyVault/Token.ps1',
        'powershell/src/KeyVault/ProvisioningKeys.ps1', 'powershell/src/KeyVault/ProvisioningTransport.ps1',
        'powershell/src/KeyVault/ProvisioningApplication.ps1', 'powershell/src/KeyVault/ProvisioningResources.ps1', 'powershell/src/KeyVault/ProvisioningSecrets.ps1',
        'powershell/src/Entra/SoftwareBrowserHeaders.ps1', 'powershell/src/Entra/SoftwareSession.ps1', 'powershell/src/Entra/SoftwareAuthorization.ps1', 'powershell/src/Entra/SoftwareAuthentication.ps1',
        'powershell/src/Entra/KeyVaultRegistrationAttestation.ps1', 'powershell/src/Entra/KeyVaultRegistrationState.ps1',
        'powershell/src/Entra/KeyVaultRegistrationRequests.ps1', 'powershell/src/Entra/KeyVaultRegistrationVerification.ps1', 'powershell/src/Entra/KeyVaultRegistrationOutput.ps1',
        'powershell/src/Public/Initialize-EntraPasskeyKeyVault.ps1', 'powershell/src/Public/Register-EntraKeyVaultPasskeyViaTap.ps1',
        'powershell/src/Public/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1', 'powershell/src/Public/Register-EntraKeyVaultPasskey.ps1'
    )) { . (Join-Path $root $source) }
    $script:version = '0123456789abcdef0123456789abcdef'
    $script:x = [byte[]](1..32); $script:y = [byte[]](33..64)
    # SDK commands are synthetic stubs, never imports or live sign-ins.
    function Get-MgContext { throw 'Unexpected SDK call' }
    function Invoke-MgGraphRequest { param($Method,$Uri,$Body) throw 'Unexpected SDK call' }
    function Invoke-AzRestMethod { param($Method,$Uri,$Payload) throw 'Unexpected SDK call' }
}

Describe 'Key Vault registration source contracts' {
    It 'loads function-only units without preference, global or script-state assignments' {
        $files = Get-ChildItem (Join-Path $root 'powershell/src/KeyVault/Provisioning*.ps1'),(Join-Path $root 'powershell/src/Entra/KeyVaultRegistration*.ps1'),(Join-Path $root 'powershell/src/Public/*KeyVault*.ps1')
        foreach ($file in $files) {
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
            $errors.Count | Should -Be 0
            foreach ($statement in $ast.EndBlock.Statements) { $statement.GetType().Name | Should -Be 'FunctionDefinitionAst' }
            $fileContent = Get-Content $file -Raw
            $fileContent | Should -Not -Match '\$(global|script):|\$PSDefaultParameterValues|\$ErrorActionPreference\s*='
        }
    }

    It 'all explicit commands support WhatIf and perform no invocation-time I/O under WhatIf' {
        Mock New-EntraRegistrationContext { throw 'Must not run' }
        Mock Get-KeyVaultToken { throw 'Must not run' }
        Mock Get-EntraKeyVaultProvisioningContext { throw 'Must not run' }
        Mock Invoke-RestMethod { throw 'Must not run' }
        Mock Set-Content { throw 'Must not run' }
        Initialize-EntraPasskeyKeyVault -WhatIf
        Register-EntraKeyVaultPasskey -TAP 'synthetic' -UserPrincipalName 'offline@example.test' -TenantId '00000000-0000-0000-0000-000000000001' -KeyVaultName 'offline-vault' -WhatIf
        Register-EntraKeyVaultPasskeyViaTap -TAP 'synthetic' -UserPrincipalName 'offline@example.test' -TenantId '00000000-0000-0000-0000-000000000001' -KeyVaultName 'offline-vault' -WhatIf
        Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'synthetic' -KeyVaultName 'offline-vault' -WhatIf
        Should -Invoke New-EntraRegistrationContext -Times 0
        Should -Invoke Get-KeyVaultToken -Times 0
        Should -Invoke Get-EntraKeyVaultProvisioningContext -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Set-Content -Times 0
    }

    It 'forwards the curated command default display name rather than inheriting the reference TAP default' {
        Mock Register-EntraKeyVaultPasskeyViaTap {}
        Register-EntraKeyVaultPasskey -TAP 'synthetic' -UserPrincipalName 'offline@example.test' -TenantId '00000000-0000-0000-0000-000000000001' -KeyVaultName 'offline-vault' -Confirm:$false
        Should -Invoke Register-EntraKeyVaultPasskeyViaTap -Times 1 -ParameterFilter { $DisplayName -eq '' }
    }

    It 'preserves none attestation with AT-only flags and explicit challenge encoding' {
        $credentialBytes = [byte[]](65..96)
        $a = New-EntraKeyVaultAttestation -PublicX $x -PublicY $y -ServerChallenge 'offline-challenge' -CredentialIdBytes $credentialBytes
        $a.AuthenticatorData[32] | Should -Be 0x40
        @($a.AuthenticatorData[33..36] | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        $client = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $a.ClientDataJson)) | ConvertFrom-Json
        $client.type | Should -Be 'webauthn.create'
        $client.challenge | Should -Be (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('offline-challenge')))
        $attestation = ConvertFrom-Base64Url $a.AttestationObject
        [Text.Encoding]::ASCII.GetString($attestation) | Should -Match 'none'
        [Text.Encoding]::ASCII.GetString($attestation) | Should -Not -Match 'packed|x5c'
        { New-EntraKeyVaultAttestation -PublicX ([byte[]](1..31)) -PublicY $y -ServerChallenge 'offline' } | Should -Throw
    }
}

Describe 'Key creation and immutable registration references' {
    BeforeEach {
        Mock Invoke-RestMethod {
            [pscustomobject]@{ key = [pscustomobject]@{ kty = 'EC'; crv = 'P-256'; x = ConvertTo-Base64Url $x; y = ConvertTo-Base64Url $y; kid = "https://offline-vault.vault.azure.net/keys/offline-key/$version" } }
        }
    }
    It 'returns the exact stored version and requests an EC P-256 key without following redirects' {
        $key = New-EntraKeyVaultRegistrationKey -VaultName 'offline-vault' -KeyName 'offline-key' -UserPrincipalName 'offline@example.test' -AccessToken 'synthetic'
        $key.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        $key.PublicX.Length | Should -Be 32
        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter { $MaximumRedirection -eq 0 -and $Method -eq 'POST' -and ($Body | ConvertFrom-Json).crv -eq 'P-256' }
    }
    It 'rejects a mismatched response host or key name' {
        Mock Invoke-RestMethod { @{ key = @{ kid = "https://other-vault.vault.azure.net/keys/offline-key/$version"; kty='EC';crv='P-256';x=ConvertTo-Base64Url $x;y=ConvertTo-Base64Url $y } } }
        { New-EntraKeyVaultRegistrationKey -VaultName 'offline-vault' -KeyName 'offline-key' -UserPrincipalName 'offline@example.test' -AccessToken 'synthetic' } | Should -Throw
    }
    It 'rejects a missing or unversioned returned key ID' {
        foreach ($id in @('', 'https://offline-vault.vault.azure.net/keys/offline-key')) {
            Mock Invoke-RestMethod { @{ key = @{ kid = $id; kty='EC';crv='P-256';x=ConvertTo-Base64Url $x;y=ConvertTo-Base64Url $y } } }
            { New-EntraKeyVaultRegistrationKey -VaultName 'offline-vault' -KeyName 'offline-key' -UserPrincipalName 'offline@example.test' -AccessToken 'synthetic' } | Should -Throw
        }
    }
    It 'rejects bad input before transmitting any token' {
        { New-EntraKeyVaultRegistrationKey -VaultName 'evil.test/path' -KeyName 'offline-key' -UserPrincipalName 'offline@example.test' -AccessToken 'synthetic' } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 0
    }
    It 'writes only public metadata and refuses an unversioned record before writing' {
        Mock Set-Content {}
        $context = [pscustomobject]@{ UserPrincipalName = 'offline@example.test' }
        $request = @{ UserHandle = 'offline-handle' }
        $attestation = New-EntraKeyVaultAttestation -PublicX $x -PublicY $y -ServerChallenge 'offline'
        $key = @{ vaultName='offline-vault';keyName='offline-key';keyId="https://offline-vault.vault.azure.net/keys/offline-key/$version" }
        $record = Save-EntraKeyVaultRegistrationRecord -Context $context -Request $request -Attestation $attestation -KeyVaultInfo $key -DisplayName 'offline' -OutputPath 'offline.json'
        $record.keyVault.keyId | Should -Be $key.keyId
        ($record | ConvertTo-Json -Depth 6) | Should -Not -Match 'AccessToken|PrivateKey|synthetic'
        $key.keyId = 'https://offline-vault.vault.azure.net/keys/offline-key'
        { Save-EntraKeyVaultRegistrationRecord -Context $context -Request $request -Attestation $attestation -KeyVaultInfo $key -DisplayName 'offline' -OutputPath 'offline.json' } | Should -Throw
        Should -Invoke Set-Content -Times 1
    }
}

Describe 'Native request state and completion validation' {
    It 'rejects hostile URLs before creating an enrollment request' {
        $context = New-EntraRegistrationContext
        $context.TenantId = 'offline'
        Mock Invoke-EntraRegistrationRestMethod { @{ Data = '{"requestData":{"canary":"c","serverChallenge":"s","userId":"u","postBackUrl":"https://evil.example.test/post"},"provisionUrl":"https://login.microsoft.com/offline/fido/create"}' } }
        { Initialize-EntraRegistrationRequest -Context $context } | Should -Throw
    }
    It 'keeps canary and postinfo on the supplied state object' {
        $state = @{ Canary = 'old'; PostInfo = ''; RedirectUrl = '' }
        Update-EntraKeyVaultRegistrationState -State $state -Content '<div id="context" data-content="{&quot;Canary&quot;:&quot;next&quot;,&quot;PostInfo&quot;:&quot;info&quot;}"><div id="redirectUrl" data-content="https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=last&amp;postinfo=final">'
        $state.Canary | Should -Be 'last'
        $state.PostInfo | Should -Be 'final'
    }
    It 'preserves existing URL query parameters when appending correlation values' {
        $uri = Add-EntraKeyVaultRegistrationQuery -Uri 'https://mysignins.microsoft.com/post?existing=value' -CorrelationId 'offline' -IncludeRegion
        $uri | Should -Match 'existing=value'
        $uri | Should -Match 'cid=offline'
        $uri | Should -Match 'mysignins-region=westus2'
    }
    It 'requires successful HTTP and finalization state without treating the service ID as WebAuthn ID' {
        $response = @{ VerificationState = 2; ErrorCode = 0; DataUpdates = @{ FidoDevices = @(@{ CredentialId = 'expected' }) } }
        Assert-EntraRegistrationFinalized -StatusCode 200 -Response $response | Should -Not -BeNullOrEmpty
        { Assert-EntraRegistrationFinalized -StatusCode 400 -Response $response } | Should -Throw
        $response.VerificationState = 1
        { Assert-EntraRegistrationFinalized -StatusCode 200 -Response $response } | Should -Throw
    }
    It 'switches to context PostInfo after ErrorCode20 State3 and succeeds only for the same credential' {
        $context = New-EntraRegistrationContext
        $request = @{ Canary='offline';PostInfo='post-info' }
        $attestation = @{ CredentialId='expected';AttestationObject='offline';ClientDataJson='offline';ClientExtensionResults='offline' }
        $script:verifyCalls = 0
        Mock Invoke-EntraRegistrationWebRequest {
            $script:verifyCalls++
            if ($script:verifyCalls -eq 1) { return @{ StatusCode=200;Content='{"ErrorCode":20,"VerificationState":3}' } }
            if (($Body | ConvertFrom-Json).CredentialVerification) {
                (($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json).CredentialId | Should -Be expected
                return @{ StatusCode=200;Content='{"ErrorCode":0,"VerificationState":2}' }
            }
            ($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json | ForEach-Object { $_.PostInfo | Should -Be 'post-info' }
            @{ StatusCode=200;Content='{"ErrorCode":0,"VerificationState":2,"DataUpdates":{"FidoDevices":{"CredentialId":"expected"}}}' }
        }
        $response = Invoke-EntraKeyVaultRegistrationVerification -Context $context -Request $request -Attestation $attestation -DisplayName 'offline' -RetryDelaySeconds 0
        $response.VerificationState | Should -Be 2
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 3
    }
}

Describe 'Explicit provisioning safety and request behavior' {
    It 'preserves existing Graph and unrelated application permissions when adding the passkey role' {
        $script:patchedApplication = $null
        Mock Invoke-MgGraphRequest {
            if ($Method -eq 'GET' -and $Uri -match '/applications\?') {
                return @{ value = @(@{ id='app-object';appId='app-id';requiredResourceAccess=@(
                    @{ resourceAppId='unrelated-app';resourceAccess=@(@{id='other-role';type='Role'}) },
                    @{ resourceAppId='00000003-0000-0000-c000-000000000000';resourceAccess=@(@{id='existing-graph-role';type='Role'}) }
                ) }) }
            }
            if ($Method -eq 'GET' -and $Uri -match '/servicePrincipals\?' -and $Uri -match '00000003') {
                return @{ value=@(@{ id='graph-object';appRoles=@(@{id='passkey-role';value='UserAuthenticationMethod.ReadWrite.All';allowedMemberTypes=@('Application')}) }) }
            }
            if ($Method -eq 'GET' -and $Uri -match '/servicePrincipals\?') { return @{value=@(@{id='service-principal'})} }
            if ($Method -eq 'PATCH') { $script:patchedApplication = $Body | ConvertFrom-Json; return }
            throw 'Unexpected Graph request'
        }
        $app = Initialize-EntraKeyVaultProvisioningApplication -ServicePrincipalName "Offline's App" -CanGrantConsent:$false -WarningAction SilentlyContinue
        $app.ApplicationId | Should -Be 'app-id'
        $app.ConsentGranted | Should -BeFalse
        @($patchedApplication.requiredResourceAccess).Count | Should -Be 2
        $graph = $patchedApplication.requiredResourceAccess | Where-Object resourceAppId -EQ '00000003-0000-0000-c000-000000000000'
        @($graph.resourceAccess.id) | Should -Contain 'existing-graph-role'
        @($graph.resourceAccess.id) | Should -Contain 'passkey-role'
        $other = $patchedApplication.requiredResourceAccess | Where-Object resourceAppId -EQ 'unrelated-app'
        $other.resourceAccess.id | Should -Be 'other-role'
    }
    It 'refuses ambiguous applications before modifying any resource' {
        Mock Invoke-MgGraphRequest { @{value=@(@{id='first'},@{id='second'})} }
        { Initialize-EntraKeyVaultProvisioningApplication -ServicePrincipalName 'duplicate' -CanGrantConsent:$false } | Should -Throw
        Should -Invoke Invoke-MgGraphRequest -Times 1
    }
    It 'does not create a resource group when an existing-resource read is denied' {
        Mock Invoke-EntraKeyVaultProvisioningArmRequest { throw 'HTTP 403: denied' }
        { Initialize-EntraKeyVaultProvisioningResourceGroup -SubscriptionId 'offline' -ResourceGroupName 'offline' -Location 'eastus' } | Should -Throw
        Should -Invoke Invoke-EntraKeyVaultProvisioningArmRequest -Times 1 -ParameterFilter { $Method -eq 'GET' }
        Should -Invoke Invoke-EntraKeyVaultProvisioningArmRequest -Times 0 -ParameterFilter { $Method -eq 'PUT' }
    }
    It 'creates a missing resource group only after a not-found read' {
        Mock Invoke-EntraKeyVaultProvisioningArmRequest {
            if ($Method -eq 'GET') { throw 'HTTP 404: ResourceNotFound' }
            @{StatusCode=200;Content='{}'}
        }
        Initialize-EntraKeyVaultProvisioningResourceGroup -SubscriptionId 'offline' -ResourceGroupName 'offline' -Location 'eastus'
        Should -Invoke Invoke-EntraKeyVaultProvisioningArmRequest -Times 1 -ParameterFilter { $Method -eq 'PUT' -and ($Payload | ConvertFrom-Json).location -eq 'eastus' }
    }
    It 'retries only transient ARM failures with the original request' {
        $script:armCount = 0
        Mock Start-Sleep {}
        Mock Invoke-AzRestMethod {
            $script:armCount++
            if ($armCount -eq 1) { @{StatusCode=503;Content='{"error":{"code":"Unavailable","message":"temporary"}}'} }
            else { @{StatusCode=200;Content='{}'} }
        }
        $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri 'https://management.azure.com/offline' -Payload '{"test":true}' -RetryDelaySeconds 0
        $response.StatusCode | Should -Be 200
        Should -Invoke Invoke-AzRestMethod -Times 2 -ParameterFilter { $Method -eq 'PUT' -and $Payload -eq '{"test":true}' }
        Should -Invoke Start-Sleep -Times 1
    }
    It 'does not contact a hostile ARM URI' {
        Mock Invoke-AzRestMethod { throw 'Must not run' }
        { Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri 'https://evil.example.test/offline' } | Should -Throw
        Should -Invoke Invoke-AzRestMethod -Times 0
    }
    It 'rejects an existing non-RBAC vault without changing its authorization' {
        Mock Invoke-EntraKeyVaultProvisioningArmRequest { @{ StatusCode=200;Content='{"properties":{"tenantId":"offline","enableRbacAuthorization":false}}' } }
        { Initialize-EntraKeyVaultProvisioningVault -SubscriptionId 'offline' -TenantId 'offline' -ResourceGroupName 'offline' -VaultName 'offline-vault' -Location 'eastus' } | Should -Throw
        Should -Invoke Invoke-EntraKeyVaultProvisioningArmRequest -Times 1 -ParameterFilter { $Method -eq 'GET' }
        Should -Invoke Invoke-EntraKeyVaultProvisioningArmRequest -Times 0 -ParameterFilter { $Method -ne 'GET' }
    }
    It 'does not finalize or write a credential if challenge registration fails' {
        $context = New-EntraRegistrationContext
        $request = @{Canary='offline';ServerChallenge='offline';UserHandle='offline';ProvisionUrl='https://login.microsoft.com/offline/fido/create';PostBackUrl='https://mysignins.microsoft.com/api/post/newfido';CorrelationId='offline';ExcludeCredentials='[]';PostInfo='';RedirectUrl=''}
        $attestation = @{CredentialId='offline';ClientDataJson='offline';AttestationObject='offline';ClientExtensionResults='offline'}
        Mock Invoke-EntraRegistrationWebRequest { @{StatusCode=400;Content='failure'} }
        Mock Invoke-EntraKeyVaultRegistrationVerification { throw 'Must not run' }
        Mock Set-Content { throw 'Must not run' }
        { Submit-EntraRegistration -Context $context -Request $request -Attestation $attestation -DisplayName 'offline' } | Should -Throw
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1
        Should -Invoke Invoke-EntraKeyVaultRegistrationVerification -Times 0
        Should -Invoke Set-Content -Times 0
    }
}

Describe 'Complete public Key Vault enrollment with synthetic transport responses' {
    BeforeEach {
        $script:failureStage = ''
        $script:authState = ''
        $script:writtenRecord = $null
        $script:tenant = '00000000-0000-0000-0000-000000000001'
        $claims = @{ aud='19db86c3-b2b9-44cc-b339-36da233a3be2';tid=$tenant;upn='offline@example.test';exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() } | ConvertTo-Json -Compress
        $script:registrationToken = 'e30.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($claims))) + '.c2lnbmF0dXJl'
        Mock Start-Sleep {}
        Mock Invoke-RestMethod {
            if ($failureStage -eq 'create') { throw 'Synthetic key creation failure' }
            if ($failureStage -eq 'provider-secret') { throw 'RAW_PROVIDER_SECRET_fixture-access-token' }
            @{ key=@{kid="https://offline-vault.vault.azure.net/keys/offline-key/$version";kty='EC';crv='P-256';x=ConvertTo-Base64Url $x;y=ConvertTo-Base64Url $y} }
        }
        Mock Set-Content {
            if ($failureStage -eq 'output') { throw 'Synthetic output failure' }
            $script:writtenRecord = $Value | ConvertFrom-Json
        }
        Mock Invoke-EntraRegistrationWebRequest {
            if ($Uri -match '/authorize\?') {
                $fields = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)
                $script:authState = $fields['state']
                if ($failureStage -eq 'auth') { return @{StatusCode=400;Content='auth denied'} }
                if ($fields['prompt'] -eq 'none') { return @{StatusCode=302;Headers=@{Location="https://mysignins.microsoft.com/#code=offline-code&state=$authState"}} }
                return @{StatusCode=200;Content='$Config={"pgid":"ConvergedSignIn","sFT":"offline-ft","sCtx":"offline-ctx","canary":"offline-canary","apiCanary":"offline-api","sessionId":"offline-session","urlPost":"/common/login"};'}
            }
            if ($Uri -match '/GetCredentialType\?') { return @{StatusCode=200;Content='{"FlowToken":"offline-ft2"}'} }
            if ($Uri -match '/common/login$') { return @{StatusCode=302;Headers=@{Location="https://mysignins.microsoft.com/#code=offline-code&state=$authState"}} }
            if ($Uri -match '/oauth2/v2.0/token$') {
                $tokenFields = [Web.HttpUtility]::ParseQueryString([string]$Body)
                $tokenFields['claims'] | Should -Match 'ngcmfa'
                return @{StatusCode=200;Content=(@{access_token=$registrationToken;refresh_token='offline-refresh'} | ConvertTo-Json -Compress)}
            }
            if ($Uri -match '/api/session/authorize$') { return @{StatusCode=200;Content='{"isAuthorized":true,"sessionCtxV2":"offline-session"}'} }
            if ($Uri -match '/api/authenticationmethods/new$') {
                return @{StatusCode=200;Content='{"ErrorCode":0,"Data":"{\"requestData\":{\"canary\":\"offline-canary\",\"serverChallenge\":\"offline-challenge\",\"userId\":\"offline-userhandle\",\"postBackUrl\":\"https://mysignins.microsoft.com/api/post/newfido\"},\"provisionUrl\":\"https://login.microsoft.com/offline/fido/create\"}"}'}
            }
            if ($Uri -match '/fido/create\?') { return @{StatusCode=200;Content='created'} }
            if ($Uri -match '/api/post/newfido\?') { return @{StatusCode=200;Content='<div id="context" data-content="{&quot;Canary&quot;:&quot;updated-canary&quot;,&quot;PostInfo&quot;:&quot;offline-postinfo&quot;}">'} }
            if ($Uri -match '/api/authenticationmethods/verify$') {
                if ($failureStage -eq 'verify') { return @{StatusCode=200;Content='{"ErrorCode":21,"VerificationState":3}'} }
                $verification = ($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json
                if (-not ($Body | ConvertFrom-Json).CredentialVerification) { $verification.Canary | Should -Be 'updated-canary' }
                return @{StatusCode=200;Content=(@{ErrorCode=0;VerificationState=2;DataUpdates=@{FidoDevices=@{CredentialId=$verification.CredentialId}}} | ConvertTo-Json -Depth 6 -Compress)}
            }
            if ($Uri -match '/api/authenticationmethods') { return @{StatusCode=200;Content='{}'} }
            throw "Unexpected synthetic request: $Uri"
        }
    }
    It 'completes TAP authentication, key creation, verified enrollment and record output through public command' {
        $record = Register-EntraKeyVaultPasskeyViaTap -TAP 'offline-tap' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.credentialId | Should -Be $writtenRecord.credentialId
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        $record.userHandle | Should -Be 'offline-userhandle'
        Should -Invoke Invoke-RestMethod -Times 1
        Should -Invoke Set-Content -Times 1
    }
    It 'emits one warning through the curated wrapper and none under WhatIf' {
        $warnings = @()
        $record = Register-EntraKeyVaultPasskey -TAP 'offline-tap' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false -WarningVariable warnings
        $record.credentialId | Should -Not -BeNullOrEmpty
        @($warnings).Count | Should -Be 1
        $warnings = @()
        Register-EntraKeyVaultPasskey -TAP 'offline-tap' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -WhatIf -WarningVariable warnings
        @($warnings).Count | Should -Be 0
    }
    It 'completes cookie authentication with resolved user and tenant through public command' {
        $record = Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'offline-cookie' -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.userName | Should -Be 'offline@example.test'
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        Should -Invoke Invoke-RestMethod -Times 1
        Should -Invoke Set-Content -Times 1
    }
    It 'does not save an enrollment when TAP authentication, key creation or verification fails' {
        foreach ($stage in @('auth','create','verify')) {
            $script:failureStage = $stage
            { Register-EntraKeyVaultPasskeyViaTap -TAP 'offline-tap' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false } | Should -Throw
        }
        Should -Invoke Set-Content -Times 0
    }
    It 'redacts provider failures on every captured public-command stream for TAP and ESTS' {
        $script:failureStage = 'provider-secret'
        foreach ($mode in @('tap','ests')) {
            $text = & {
                try {
                    if ($mode -eq 'tap') { Register-EntraKeyVaultPasskeyViaTap -TAP 'offline' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false }
                    else { Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'offline' -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false }
                } catch { $_ | Out-String; $_.Exception.ToString() }
            } *>&1 | Out-String
            $text | Should -Not -Match 'RAW_PROVIDER_SECRET|fixture-access-token'
            $text | Should -Match 'service details suppressed'
            $text | Should -Match 'No rollback was attempted'
        }
        Should -Invoke Set-Content -Times 0
    }

    It 'surfaces an output write failure rather than returning a completed record' {
        $script:failureStage = 'output'
        $failure = $null
        try { Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'offline-cookie' -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false }
        catch { $failure = $_ }
        $failure.Exception.Message | Should -Match 'enrollment was confirmed'
        $failure.Exception.Message | Should -Match 'not rolled back'
        $failure.TargetObject.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        ($failure.TargetObject | ConvertTo-Json -Depth 5) | Should -Not -Match 'AccessToken|PrivateKey'
        Should -Invoke Set-Content -Times 1
    }
}

Describe 'Complete initializer with synthetic Graph, ARM and credential transport' {
    BeforeEach {
        $script:tenant = '00000000-0000-0000-0000-000000000001'
        $script:subscription = '00000000-0000-0000-0000-000000000002'
        $script:vaultCreated = $false; $script:roleCreated = $false; $script:createdSecret = 'SYNTHETIC-CLIENT-SECRET-DO-NOT-USE'
        Mock Get-MgContext { @{TenantId=$tenant;Scopes=@('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All')} }
        function Get-AzContext { @{Account=@{Id='offline@example.test'};Tenant=@{Id=$tenant};Subscription=@{Id=$subscription;Name='offline'}} }
        Mock Start-Sleep {}
        Mock Invoke-MgGraphRequest {
            if ($Method -eq 'GET' -and $Uri -match '/applications\?') { return @{value=@()} }
            if ($Method -eq 'POST' -and $Uri -eq 'https://graph.microsoft.com/v1.0/applications') { return @{id='offline-app-object';appId='offline-app-id'} }
            if ($Method -eq 'GET' -and $Uri -match '/servicePrincipals\?' -and $Uri -match '00000003') {
                return @{value=@(@{id='offline-graph-sp';appRoles=@(@{id='offline-passkey-role';value='UserAuthenticationMethod.ReadWrite.All';allowedMemberTypes=@('Application')})})}
            }
            if ($Method -eq 'GET' -and $Uri -match '/servicePrincipals\?') { return @{value=@()} }
            if ($Method -eq 'POST' -and $Uri -eq 'https://graph.microsoft.com/v1.0/servicePrincipals') { return @{id='offline-sp'} }
            if ($Method -eq 'PATCH' -and $Uri -match '/applications/') { return }
            if ($Method -eq 'GET' -and $Uri -match '/appRoleAssignments$') { return @{value=@()} }
            if ($Method -eq 'POST' -and $Uri -match '/appRoleAssignments$') { return }
            if ($Method -eq 'POST' -and $Uri -match '/addPassword$') { return @{secretText=$createdSecret} }
            throw "Unexpected synthetic Graph request: $Method $Uri"
        }
        Mock Invoke-AzRestMethod {
            if ($Method -eq 'GET' -and $Uri -match '/roleDefinitions\?') { return @{StatusCode=200;Content=(@{value=@(@{id="/subscriptions/$subscription/providers/Microsoft.Authorization/roleDefinitions/offline-role"})}|ConvertTo-Json -Depth 5 -Compress)} }
            if ($Method -eq 'GET' -and $Uri -match '/roleAssignments\?') {
                $roles = if ($roleCreated) { @(@{properties=@{principalId='offline-sp';roleDefinitionId="/subscriptions/$subscription/providers/Microsoft.Authorization/roleDefinitions/offline-role"}}) } else { @() }
                return @{StatusCode=200;Content=(@{value=$roles}|ConvertTo-Json -Depth 6 -Compress)}
            }
            if ($Method -eq 'PUT' -and $Uri -match '/roleAssignments/') { $script:roleCreated=$true;return @{StatusCode=201;Content='{}'} }
            if ($Method -eq 'POST' -and $Uri -match '/checkNameAvailability\?') { return @{StatusCode=200;Content='{"nameAvailable":true}'} }
            if ($Method -eq 'PUT' -and $Uri -match '/vaults/offline-vault\?') { $script:vaultCreated=$true;return @{StatusCode=201;Content='{}'} }
            if ($Method -eq 'GET' -and $Uri -match '/vaults/offline-vault\?') {
                if (-not $vaultCreated) { return @{StatusCode=404;Content='{"error":{"code":"ResourceNotFound"}}'} }
                return @{StatusCode=200;Content=(@{properties=@{tenantId=$tenant;enableRbacAuthorization=$true;enablePurgeProtection=$true}} |ConvertTo-Json -Depth 5 -Compress)}
            }
            if ($Method -eq 'GET' -and $Uri -match '/resourceGroups/offline-rg\?') { return @{StatusCode=404;Content='{"error":{"code":"ResourceNotFound"}}'} }
            if ($Method -eq 'PUT' -and $Uri -match '/resourceGroups/offline-rg\?') { return @{StatusCode=201;Content='{}'} }
            throw "Unexpected synthetic ARM request: $Method $Uri"
        }
        Mock Invoke-RestMethod {
            $Body.client_secret | Should -Be $createdSecret
            $MaximumRedirection | Should -Be 0
            @{access_token='synthetic-service-token'}
        }
    }
    It 'provisions resources and returns the historical explicit PassThru result shape without secret diagnostics' {
        $streams = @(Initialize-EntraPasskeyKeyVault -SubscriptionId $subscription -ResourceGroupName 'offline-rg' -KeyVaultName 'offline-vault' -ServicePrincipalName 'offline-app' -PassThru -Confirm:$false *>&1)
        $result = @($streams | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties.Name -contains 'TenantId' })[0]
        $result.ApplicationId | Should -Be 'offline-app-id'
        $result.ServicePrincipalId | Should -Be 'offline-sp'
        $result.ClientSecret | Should -Be $createdSecret
        $result.ConsentGranted | Should -BeTrue
        $result.UseKeyVault | Should -BeTrue
        @($result.PSObject.Properties.Name | Sort-Object) -join ',' | Should -Be 'ApplicationId,ClientSecret,ConsentGranted,KeyVaultName,KeyVaultSku,Location,ResourceGroupName,SecretExpiration,ServicePrincipalId,ServicePrincipalName,SubscriptionId,TenantId,UseKeyVault'
        $diagnostics = $streams | Where-Object { $_ -ne $result } | Out-String
        $diagnostics | Should -Not -Match $createdSecret
        Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Uri -match '/addPassword$' }
        Should -Invoke Invoke-AzRestMethod -Times 1 -ParameterFilter { $Method -eq 'PUT' -and $Uri -match '/vaults/offline-vault\?' }
        Should -Invoke Invoke-RestMethod -Times 2
    }
    It 'skips client-secret creation entirely when requested' {
        Initialize-EntraPasskeyKeyVault -SubscriptionId $subscription -ResourceGroupName 'offline-rg' -KeyVaultName 'offline-vault' -ServicePrincipalName 'offline-app' -SkipSecret -Confirm:$false
        Should -Invoke Invoke-MgGraphRequest -Times 0 -ParameterFilter { $Uri -match '/addPassword$' }
        Should -Invoke Invoke-RestMethod -Times 0
    }
    It 'redacts raw Graph SDK failures and explains possible partial provisioning' {
        Mock Invoke-MgGraphRequest { throw 'RAW_SDK_SECRET_fixture-client-secret' }
        $text = & {
            try { Initialize-EntraPasskeyKeyVault -SubscriptionId $subscription -ResourceGroupName 'offline-rg' -KeyVaultName 'offline-vault' -ServicePrincipalName 'offline-app' -PassThru -Confirm:$false }
            catch { $_ | Out-String; $_.Exception.ToString() }
        } *>&1 | Out-String
        $text | Should -Not -Match 'RAW_SDK_SECRET|fixture-client-secret'
        $text | Should -Match 'Resources, permissions or client credentials may already have been created'
        $text | Should -Match 'No rollback was attempted'
    }

    It 'refuses to create or discard a secret without PassThru before any provisioning I/O' {
        { Initialize-EntraPasskeyKeyVault -SubscriptionId $subscription -ResourceGroupName 'offline-rg' -KeyVaultName 'offline-vault' -ServicePrincipalName 'offline-app' -Confirm:$false } | Should -Throw -ExpectedMessage '*Client secret creation requires -PassThru*'
        Should -Invoke Get-MgContext -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Should -Invoke Invoke-AzRestMethod -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
    }
    It 'allows vault-only provisioning without PassThru or creating a secret' {
        Initialize-EntraPasskeyKeyVault -SubscriptionId $subscription -ResourceGroupName 'offline-rg' -KeyVaultName 'offline-vault' -SkipServicePrincipal -Confirm:$false
        Should -Invoke Get-MgContext -Times 1
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
    }
}
