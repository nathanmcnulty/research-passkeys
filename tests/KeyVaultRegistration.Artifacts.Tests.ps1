BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    $script:manifest = Import-PowerShellDataFile (Join-Path $root 'build/targets.psd1')
    $script:modulePath = Join-Path $root 'powershell/modules/Passkey/Passkey.psd1'
    Import-Module $modulePath -Force
    $script:moduleName = 'Passkey'
    & (Get-Module Passkey) { function script:Get-MgContext { [CmdletBinding()]param() throw 'Unexpected SDK call' } }
    $script:tenant = '00000000-0000-0000-0000-000000000001'
    $script:version = '0123456789abcdef0123456789abcdef'
    $script:x64 = [Convert]::ToBase64String([byte[]](1..32)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $script:y64 = [Convert]::ToBase64String([byte[]](33..64)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $claims = @{aud='19db86c3-b2b9-44cc-b339-36da233a3be2';tid=$tenant;upn='offline@example.test';exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()} | ConvertTo-Json -Compress
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $script:registrationToken = "e30.$payload.c2lnbmF0dXJl"
    $script:webBoundary = {
        if ($Uri -eq 'about:synthetic-mock-check') { return @{StatusCode=200;Content='mock-only'} }
        $MaximumRedirection | Should -Be 0
        if ($Uri -match '/authorize\?') {
            $query = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)
            $script:authState = $query['state']
            if ($query['prompt'] -eq 'none') { return @{StatusCode=302;Headers=@{Location="https://mysignins.microsoft.com/#code=offline-code&state=$authState"}} }
            return @{StatusCode=200;Content='$Config={"pgid":"ConvergedSignIn","sFT":"offline-ft","sCtx":"offline-ctx","canary":"offline-canary","apiCanary":"offline-api","sessionId":"offline-session","urlPost":"/common/login"};'}
        }
        if ($Uri -match '/GetCredentialType\?') { return @{StatusCode=200;Content='{"FlowToken":"offline-ft2"}'} }
        if ($Uri -match '/common/login$') { return @{StatusCode=302;Headers=@{Location="https://mysignins.microsoft.com/#code=offline-code&state=$authState"}} }
        if ($Uri -match '/oauth2/v2.0/token$') {
            ([Web.HttpUtility]::ParseQueryString([string]$Body))['claims'] | Should -Match 'ngcmfa'
            return @{StatusCode=200;Content=(@{access_token=$registrationToken;refresh_token='offline-refresh'} |ConvertTo-Json -Compress)}
        }
        if ($Uri -match '/api/session/authorize$') { return @{StatusCode=200;Content='{"isAuthorized":true,"sessionCtxV2":"offline-session"}'} }
        if ($Uri -match '/api/authenticationmethods/new$') { return @{StatusCode=200;Content='{"ErrorCode":0,"Data":"{\"requestData\":{\"canary\":\"offline-canary\",\"serverChallenge\":\"offline-challenge\",\"userId\":\"offline-handle\",\"postBackUrl\":\"https://mysignins.microsoft.com/api/post/newfido\"},\"provisionUrl\":\"https://login.microsoft.com/offline/fido/create\"}"}'} }
        if ($Uri -match '/fido/create\?') { return @{StatusCode=200;Content='created'} }
        if ($Uri -match '/api/post/newfido\?') { return @{StatusCode=200;Content='<div id="context" data-content="{&quot;Canary&quot;:&quot;updated-canary&quot;,&quot;PostInfo&quot;:&quot;offline-postinfo&quot;}">'} }
        if ($Uri -match '/api/authenticationmethods/verify$') {
            $verified = ($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json
            $verified.Canary | Should -Be 'updated-canary'
            return @{StatusCode=200;Content=(@{ErrorCode=0;VerificationState=2;DataUpdates=@{FidoDevices=@{CredentialId=$verified.CredentialId}}}|ConvertTo-Json -Depth 6 -Compress)}
        }
        if ($Uri -match '/api/authenticationmethods') { return @{StatusCode=200;Content='{}'} }
        throw "Unexpected synthetic request: $Uri"
    }
    $script:keyBoundary = {
        $MaximumRedirection | Should -Be 0
        $Uri | Should -Be 'https://offline-vault.vault.azure.net/keys/offline-key/create?api-version=7.4'
        @{key=@{kid="https://offline-vault.vault.azure.net/keys/offline-key/$version";kty='EC';crv='P-256';x=$x64;y=$y64}}
    }
    $script:fileBoundary = { $script:writtenRecord = $Value | ConvertFrom-Json }
    function Get-MgContext { [CmdletBinding()]param() throw 'Unexpected SDK call' }
}
AfterAll { Remove-Module Passkey -ErrorAction SilentlyContinue }

Describe 'Generated Key Vault standalone and module contracts' {
    It 'retains every baseline named parameter on standalone entrypoints and exported commands' {
        $contracts = @{
            'Initialize-EntraPasskeyKeyVault' = @('SubscriptionId','ResourceGroupName','KeyVaultName','Location','ServicePrincipalName','KeyVaultSku','EnablePurgeProtection','SecretExpirationMonths','SkipServicePrincipal','SkipSecret','SkipKeyVault','PassThru')
            'Register-EntraKeyVaultPasskey' = @('TAP','UserPrincipalName','TenantId','KeyVaultName','KeyVaultKeyName','DisplayName','OutputPath','KeyVaultAccessToken','UserAgent','RedirectUri')
            'Register-EntraKeyVaultPasskeyViaTap' = @('TAP','UserPrincipalName','TenantId','KeyVaultName','KeyVaultKeyName','DisplayName','OutputPath','KeyVaultAccessToken','UserAgent','RedirectUri')
            'Register-EntraKeyVaultPasskeyViaEstsAuth' = @('ESTSAuthCookie','KeyVaultName','TenantId','KeyVaultKeyName','PasskeyDisplayName','OutputPath','KeyVaultAccessToken','UserAgent','RedirectUri')
        }
        foreach ($name in $contracts.Keys) {
            $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match "/$name\.ps1$" })[0]
            $target | Should -Not -BeNullOrEmpty
            $path = Join-Path $root $target.Path
            $text = Get-Content $path -Raw
            ($text -match '(?m)^# Generated by build/build.ps1') | Should -BeTrue
            $tokens=$null;$errors=$null
            $ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
            $errors.Count | Should -Be 0
            @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath | Sort-Object) -join ',' | Should -Be (@($contracts[$name] |Sort-Object) -join ',')
            $command = Get-Command $name -Module Passkey
            foreach ($parameter in $contracts[$name]) { $command.Parameters.ContainsKey($parameter) | Should -BeTrue }
            $command.Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }
    }
    It 'runs every real standalone artifact under WhatIf with all I/O boundaries blocked' {
        Mock Invoke-WebRequest { throw 'Unexpected network I/O' }
        Mock Invoke-RestMethod { throw 'Unexpected network I/O' }
        Mock Set-Content { throw 'Unexpected output I/O' }
        foreach ($target in $manifest.Scripts | Where-Object { $_.EntryPoint -match '/(Initialize-EntraPasskeyKeyVault|Register-EntraKeyVaultPasskey|Register-EntraKeyVaultPasskeyViaTap|Register-EntraKeyVaultPasskeyViaEstsAuth)\.ps1$' }) {
            $parameters = @{WhatIf=$true}
            if ($target.EntryPoint -match 'ViaEstsAuth') { $parameters.ESTSAuthCookie='offline-cookie';$parameters.KeyVaultName='offline-vault' }
            elseif ($target.EntryPoint -match '/Register-') { $parameters.TAP='offline-tap';$parameters.UserPrincipalName='offline@example.test';$parameters.TenantId=$tenant;$parameters.KeyVaultName='offline-vault' }
            & (Join-Path $root $target.Path) @parameters
        }
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Set-Content -Times 0
    }
    It 'runs every exported module command under WhatIf without network or output I/O' {
        Mock Invoke-WebRequest -ModuleName Passkey { throw 'Unexpected network I/O' }
        Mock Invoke-RestMethod -ModuleName Passkey { throw 'Unexpected network I/O' }
        Mock Set-Content -ModuleName Passkey { throw 'Unexpected output I/O' }
        Initialize-EntraPasskeyKeyVault -WhatIf
        Register-EntraKeyVaultPasskey -TAP 'offline' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -WhatIf
        Register-EntraKeyVaultPasskeyViaTap -TAP 'offline' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -WhatIf
        Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'offline' -KeyVaultName 'offline-vault' -WhatIf
        Should -Invoke Invoke-WebRequest -ModuleName Passkey -Times 0
        Should -Invoke Invoke-RestMethod -ModuleName Passkey -Times 0
        Should -Invoke Set-Content -ModuleName Passkey -Times 0
    }
}

Describe 'Whole generated Key Vault enrollment workflows' {
    BeforeEach {
        $script:authState='';$script:writtenRecord=$null
        Mock Invoke-WebRequest $webBoundary
        Mock Invoke-RestMethod $keyBoundary
        Mock Set-Content $fileBoundary
        Mock Invoke-WebRequest -ModuleName Passkey $webBoundary
        Mock Invoke-RestMethod -ModuleName Passkey $keyBoundary
        Mock Set-Content -ModuleName Passkey $fileBoundary
    }
    It 'redacts provider error markers across actual standalone and module command streams' {
        Mock Invoke-RestMethod { throw 'RAW_PROVIDER_SECRET_fixture-access-token' }
        Mock Invoke-RestMethod -ModuleName Passkey { throw 'RAW_PROVIDER_SECRET_fixture-access-token' }
        foreach ($surface in @('standalone','module')) {
            foreach ($command in @('Register-EntraKeyVaultPasskeyViaTap','Register-EntraKeyVaultPasskeyViaEstsAuth')) {
                $parameters = @{KeyVaultName='offline-vault';KeyVaultKeyName='offline-key';KeyVaultAccessToken='offline-token';OutputPath='offline.json';Confirm=$false}
                if ($command -match 'ViaTap$') { $parameters.TAP='offline';$parameters.UserPrincipalName='offline@example.test';$parameters.TenantId=$tenant }
                else { $parameters.ESTSAuthCookie='offline' }
                $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match "/$command\.ps1$" })[0]
                $text = & {
                    try {
                        if ($surface -eq 'standalone') { & (Join-Path $root $target.Path) @parameters }
                        else { & $command @parameters }
                    } catch { $_ | Out-String; $_.Exception.ToString() }
                } *>&1 | Out-String
                $text | Should -Not -Match 'RAW_PROVIDER_SECRET|fixture-access-token'
                $text | Should -Match 'service details suppressed'
                $text | Should -Match 'No rollback was attempted'
            }
        }
        Should -Invoke Set-Content -Times 0
        Should -Invoke Set-Content -ModuleName Passkey -Times 0
    }
    It 'redacts initializer SDK failures across actual standalone and module command streams' {
        Mock Get-MgContext { throw 'RAW_SDK_SECRET_fixture-client-secret' }
        Mock Get-MgContext -ModuleName Passkey { throw 'RAW_SDK_SECRET_fixture-client-secret' }
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Initialize-EntraPasskeyKeyVault\.ps1$' })[0]
        foreach ($surface in @('standalone','module')) {
            $text = & {
                try {
                    if ($surface -eq 'standalone') { & (Join-Path $root $target.Path) -SkipKeyVault -SkipSecret -Confirm:$false }
                    else { Initialize-EntraPasskeyKeyVault -SkipKeyVault -SkipSecret -Confirm:$false }
                } catch { $_ | Out-String; $_.Exception.ToString() }
            } *>&1 | Out-String
            $text | Should -Not -Match 'RAW_SDK_SECRET|fixture-client-secret'
            $text | Should -Match 'Resources, permissions or client credentials may already have been created'
            $text | Should -Match 'No rollback was attempted'
        }
        Should -Invoke Get-MgContext -Times 1
        Should -Invoke Get-MgContext -ModuleName Passkey -Times 1
    }

    It 'blocks secret creation without an output capture before any standalone or module SDK I/O' {
        Mock Get-MgContext { throw 'SDK must not run' }
        Mock Get-MgContext -ModuleName Passkey { throw 'SDK must not run' }
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Initialize-EntraPasskeyKeyVault\.ps1$' })[0]
        { & (Join-Path $root $target.Path) -Confirm:$false } | Should -Throw -ExpectedMessage '*Client secret creation requires -PassThru*'
        { Initialize-EntraPasskeyKeyVault -Confirm:$false } | Should -Throw -ExpectedMessage '*Client secret creation requires -PassThru*'
        Should -Invoke Get-MgContext -Times 0
        Should -Invoke Get-MgContext -ModuleName Passkey -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke Invoke-WebRequest -ModuleName Passkey -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Invoke-RestMethod -ModuleName Passkey -Times 0
    }
    It 'allows explicit PassThru and skip cases through the standalone and module preflight' {
        Mock Get-MgContext { throw 'Synthetic SDK stop after validated preflight' }
        Mock Get-MgContext -ModuleName Passkey { throw 'Synthetic SDK stop after validated preflight' }
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Initialize-EntraPasskeyKeyVault\.ps1$' })[0]
        foreach ($parameters in @(@{PassThru=$true},@{SkipSecret=$true},@{SkipServicePrincipal=$true})) {
            $parameters.Confirm = $false
            { & (Join-Path $root $target.Path) @parameters } | Should -Throw -ExpectedMessage '*service details suppressed*'
            { Initialize-EntraPasskeyKeyVault @parameters } | Should -Throw -ExpectedMessage '*service details suppressed*'
        }
        Should -Invoke Get-MgContext -Times 3
        Should -Invoke Get-MgContext -ModuleName Passkey -Times 3
    }

    It 'warns once through the curated <Surface> wrapper and never for WhatIf' -ForEach @(@{Surface='standalone'},@{Surface='module'}) {
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Register-EntraKeyVaultPasskey\.ps1$' })[0]
        $command = if ($Surface -eq 'standalone') { Join-Path $root $target.Path } else { 'Passkey\Register-EntraKeyVaultPasskey' }
        $parameters = @{TAP='offline';UserPrincipalName='offline@example.test';TenantId=$tenant;KeyVaultName='offline-vault';KeyVaultKeyName='offline-key';KeyVaultAccessToken='offline-token';OutputPath='offline.json';Confirm=$false}
        $warnings = @()
        $record = & $command @parameters -WarningVariable warnings
        $record.credentialId | Should -Not -BeNullOrEmpty
        @($warnings).Count | Should -Be 1
        $warnings = @()
        & $command @parameters -WhatIf -WarningVariable warnings
        @($warnings).Count | Should -Be 0
    }
    It 'executes the generated TAP standalone artifact through qualified mocked transport' {
        (Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri 'about:synthetic-mock-check').StatusCode | Should -Be 200
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Register-EntraKeyVaultPasskeyViaTap\.ps1$' })[0]
        $record = & (Join-Path $root $target.Path) -TAP 'offline' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.credentialId | Should -Not -BeNullOrEmpty
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        Should -Invoke Set-Content -Times 1
    }
    It 'executes the generated ESTS standalone artifact through qualified mocked transport' {
        (Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri 'about:synthetic-mock-check').StatusCode | Should -Be 200
        $target = @($manifest.Scripts | Where-Object { $_.EntryPoint -match '/Register-EntraKeyVaultPasskeyViaEstsAuth\.ps1$' })[0]
        $record = & (Join-Path $root $target.Path) -ESTSAuthCookie 'offline' -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.userName | Should -Be 'offline@example.test'
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        Should -Invoke Set-Content -Times 1
    }
    It 'executes the exported TAP module workflow through private helpers and mocked transport' {
        (& (Get-Module Passkey) { Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri 'about:synthetic-mock-check' }).StatusCode | Should -Be 200
        $record = Register-EntraKeyVaultPasskeyViaTap -TAP 'offline' -UserPrincipalName 'offline@example.test' -TenantId $tenant -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.credentialId | Should -Not -BeNullOrEmpty
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        Should -Invoke Set-Content -ModuleName Passkey -Times 1
    }
    It 'executes the exported ESTS module workflow through private helpers and mocked transport' {
        (& (Get-Module Passkey) { Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri 'about:synthetic-mock-check' }).StatusCode | Should -Be 200
        $record = Register-EntraKeyVaultPasskeyViaEstsAuth -ESTSAuthCookie 'offline' -KeyVaultName 'offline-vault' -KeyVaultKeyName 'offline-key' -KeyVaultAccessToken 'offline-token' -OutputPath 'offline.json' -Confirm:$false
        $record.userName | Should -Be 'offline@example.test'
        $record.keyVault.keyId | Should -Be "https://offline-vault.vault.azure.net/keys/offline-key/$version"
        Should -Invoke Set-Content -ModuleName Passkey -Times 1
    }
}
