BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $manifest = Import-PowerShellDataFile "$repo/build/targets.psd1"
    $graphScript = "$repo/powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1"
    $graphSources = ($manifest.Scripts | Where-Object Path -EQ 'powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1').Sources
    $global:SoftwareGraphFixture = @{}
    $fixtureKey = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
    $fixturePublic = $fixtureKey.ExportParameters($false)
    $fixtureKey.Dispose()
}
AfterAll { Remove-Variable SoftwareGraphFixture -Scope Global }
Describe 'Complete Graph software registration through <Surface>' -ForEach @(@{ Surface = 'Source' }, @{ Surface = 'Module' }, @{ Surface = 'Standalone' }) {
    BeforeEach {
        $mockScope = @{}
        if ($Surface -eq 'Module') {
            Import-Module "$repo/powershell/modules/Passkey/Passkey.psd1" -Force
            $command = 'Passkey\Register-EntraSoftwarePasskey'
            $mockScope.ModuleName = 'Passkey'
        } elseif ($Surface -eq 'Source') {
            foreach ($source in $graphSources) { . "$repo/$source" }
            $command = 'Register-EntraSoftwarePasskey'
        } else { $command = $graphScript }
        $global:SoftwareGraphFixture.Clear(); $global:SoftwareGraphFixture.Mode = 'success'
        Mock Invoke-WebRequest {
            ([uri]$Uri).Host | Should -Be login.microsoftonline.com
            $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
            $form['client_secret'] | Should -Be 'SYNTHETIC-APPLICATION-SECRET'
            return @{ StatusCode = 200; Headers = @{}; Content = '{"access_token":"SYNTHETIC-APPLICATION-TOKEN"}' }
        } @mockScope
        Mock Invoke-RestMethod {
            if ($Uri -match '/creationOptions\(') {
                $name = if ($global:SoftwareGraphFixture.Mode -eq 'mismatch') { 'other@example.invalid' } else { 'fixture@example.invalid' }
                return @{ publicKey = @{ challenge = 'AQID'; rp = @{ id = 'login.microsoft.com' }; user = @{ id = 'BAUG'; name = $name }; pubKeyCredParams = @(@{ alg = -7; type = 'public-key' }) } }
            }
            if ($Uri -match '/keys/[^/]+/create\?') {
                $name = ([uri]$Uri).AbsolutePath.Split('/')[2]
                return @{ key = @{ kid = "https://fixture-vault.vault.azure.net/keys/$name/0123456789abcdef0123456789abcdef"; kty = 'EC'; crv = 'P-256'; x = [Convert]::ToBase64String($fixturePublic.Q.X).TrimEnd('=').Replace('+','-').Replace('/','_'); y = [Convert]::ToBase64String($fixturePublic.Q.Y).TrimEnd('=').Replace('+','-').Replace('/','_') } }
            }
            if ($Method -eq 'POST' -and $Uri -match '/authentication/fido2Methods$') {
                $request = $Body | ConvertFrom-Json
                $request.displayName | Should -Be 'Fixture software'
                $attestationBytes = [Convert]::FromBase64String($request.publicKeyCredential.response.attestationObject.Replace('-','+').Replace('_','/') + ('=' * ((4 - $request.publicKeyCredential.response.attestationObject.Length % 4) % 4)))
                [Text.Encoding]::Latin1.GetString($attestationBytes) | Should -Match 'none'
                if ($global:SoftwareGraphFixture.Mode -eq 'submitfail') { throw 'SYNTHETIC-SENSITIVE-ERROR' }
                return @{ id = 'fixture-method'; displayName = 'Fixture software'; createdDateTime = '2026-10-11T00:00:00Z' }
            }
            throw 'Unexpected mocked Graph/Key Vault request.'
        } @mockScope
        $outputPath = Join-Path $TestDrive "$Surface-$([guid]::NewGuid().ToString('N')).json"
        $parameters = @{
            UserUpn = 'fixture@example.invalid'; DisplayName = 'Fixture software'; TenantId = '11111111-1111-1111-1111-111111111111'
            ClientId = '22222222-2222-2222-2222-222222222222'; ClientSecret = ConvertTo-SecureString 'SYNTHETIC-APPLICATION-SECRET' -AsPlainText -Force
            OutputPath = $outputPath; Confirm = $false
        }
    }
    It 'persists the complete local credential and forwards only SecureString configuration under explicit PassThru' {
        $result = & $command @parameters -PassThru
        $result.CredentialFilePath | Should -Be $outputPath
        $result.ClientSecret | Should -BeOfType ([securestring])
        $result | ConvertTo-Json -Depth 5 | Should -Not -Match 'SYNTHETIC-APPLICATION-SECRET|BEGIN PRIVATE'
        $saved = Get-Content $outputPath -Raw | ConvertFrom-Json
        $saved.privateKey | Should -Match '^-----BEGIN PRIVATE KEY-----'
        $saved.userHandle | Should -Be BAUG
        $saved.relyingParty | Should -Be 'login.microsoft.com'
        if (-not $IsWindows) {
            [int][IO.File]::GetUnixFileMode($outputPath) | Should -Be ([int]([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite))
        }
    }
    It 'persists a versioned Key Vault reference and preserves KeyName without exporting a private key' {
        $result = & $command @parameters -UseKeyVault -KeyVaultName fixture-vault -PassThru
        $result.KeyName | Should -Not -BeNullOrEmpty
        $saved = Get-Content $outputPath -Raw | ConvertFrom-Json
        $saved.keyVault.keyName | Should -Be $result.KeyName
        $saved.keyVault.keyId | Should -Match '/0123456789abcdef0123456789abcdef$'
        $saved.PSObject.Properties.Name | Should -Not -Contain privateKey
    }
    It 'has no credential or application secret in the default result' {
        $result = & $command @parameters
        $result.Success | Should -BeTrue
        $result.PSObject.Properties.Name | Should -Not -Contain ClientSecret
        $result | ConvertTo-Json -Depth 5 | Should -Not -Match 'BEGIN PRIVATE|SYNTHETIC-APPLICATION-SECRET'
    }
    It 'rejects user-binding and submission failure without keeping an empty output reservation' -ForEach @('mismatch', 'submitfail') {
        $global:SoftwareGraphFixture.Mode = $_
        $caught = $null
        try { & $command @parameters } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Not -Match SYNTHETIC
        Test-Path $outputPath | Should -BeFalse
    }
    It 'returns before all network and filesystem work under WhatIf' {
        & $command @parameters -WhatIf
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly @mockScope
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly @mockScope
        Test-Path $outputPath | Should -BeFalse
    }
}
