BeforeAll {
    $repo = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $manifest = Import-PowerShellDataFile "$repo/build/targets.psd1"
    $sources = ($manifest.Scripts | Where-Object Path -EQ 'github/adapters/Register-GitHubPasskeyViaTAP.ps1').Sources
    foreach ($source in $sources) { . "$repo/$source" }
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
    $script:fixture = @{ credentialId = 'AQIDBA'; userHandle = 'BQYHCA'; userName = 'fixture@example.invalid'; privateKey = $key.ExportPkcs8PrivateKeyPem() }
    $key.Dispose()
    $script:names = @('PASSKEY_LAB_CREDENTIAL_ID','PASSKEY_LAB_USER_HANDLE','PASSKEY_LAB_USER_PRINCIPAL_NAME','PASSKEY_LAB_PRIVATE_KEY')
}
Describe 'Protected lab secret profile fails closed' {
    BeforeEach {
        Mock Invoke-GitHubPasskeyCli {}
        Mock Invoke-RestMethod { throw 'Unexpected network access' }
        Mock Invoke-WebRequest { throw 'Unexpected network access' }
        Mock Invoke-EntraRegistrationTapAuthentication { throw 'Unexpected authentication' }
        Mock Invoke-EntraSoftwareNativeRegistration { throw 'Unexpected enrollment' }
        $script:arguments = @{ Credential = $script:fixture.Clone(); Repository = 'owner/repo'; ProtectedLab = $true; Environment = 'passkey-validation'; Confirm = $false }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'preflights the exact existing environment then writes only its four fixed names over stdin' {
        $result = Export-PasskeyToGitHubSecret @script:arguments
        $result.SecretNames -join ',' | Should -BeExactly ($script:names -join ',')
        $result.SecretProfile | Should -BeExactly ProtectedLab
        $result.Environment | Should -BeExactly passkey-validation
        Should -Invoke Invoke-GitHubPasskeyCli -Times 6 -Exactly
        Should -Invoke Invoke-GitHubPasskeyCli -Times 1 -Exactly -ParameterFilter {
            ($Arguments[0..6] -join '|') -ceq 'api|--hostname|github.com|--method|GET|repos/owner/repo/environments/passkey-validation|--jq' -and $RequireProtectionSentinel
        }
        foreach ($name in $script:names) {
            Should -Invoke Invoke-GitHubPasskeyCli -Times 1 -Exactly -ParameterFilter {
                ($Arguments -join '|') -ceq "secret|set|$name|--repo|github.com/owner/repo|--app|actions|--env|passkey-validation"
            }
        }
        Should -Invoke Invoke-GitHubPasskeyCli -Times 1 -Exactly -ParameterFilter { $Arguments[2] -ceq 'PASSKEY_LAB_PRIVATE_KEY' -and $InputText -ceq $script:fixture.privateKey }
    }
    It 'rejects a missing or malformed environment without any I/O' -ForEach @('', ' ', '../prod', 'a/b', '-prod', 'x?y', "a`nb", "passkey-validation`n") {
        $script:arguments.Environment = $_
        { Export-PasskeyToGitHubSecret @script:arguments } | Should -Throw '*Environment*'
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'rejects Environment without ProtectedLab rather than falling back' {
        $script:arguments.ProtectedLab = $false
        { Export-PasskeyToGitHubSecret @script:arguments } | Should -Throw '*ProtectedLab*'
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'performs no I/O under WhatIf' {
        Export-PasskeyToGitHubSecret @script:arguments -WhatIf
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'stops on missing denied or unavailable environment without writing secrets' -ForEach @(401,403,404,500) {
        $script:status = $_
        Mock Invoke-GitHubPasskeyCli { throw (New-GitHubPasskeyCliError -Check RepositoryAccess -Category ApiFailure -HttpStatus $script:status -ExitCode 1) }
        $caught = $null
        try { Export-PasskeyToGitHubSecret @script:arguments } catch { $caught = $_ }
        $caught.TargetObject.Stage | Should -Be GitHubPreflight
        $caught.TargetObject.SecretProfile | Should -Be ProtectedLab
        Should -Invoke Invoke-GitHubPasskeyCli -Times 1 -Exactly
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'secret' }
    }
    It 'preflights before reserving a file or authenticating and enrolling' {
        Mock Invoke-GitHubPasskeyCli { throw 'DO_NOT_LEAK' }
        $path = Join-Path $TestDrive 'not-created.json'
        $caught = $null
        try {
            Register-GitHubPasskeyViaTAP -TAP (ConvertTo-SecureString 'synthetic-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -Repository owner/repo -ProtectedLab -Environment passkey-validation -RecoveryOutputPath $path -Confirm:$false
        } catch { $caught = $_ }
        $caught.TargetObject.Stage | Should -Be GitHubPreflight
        $caught.TargetObject.EnrollmentStatus | Should -Be NotStarted
        $caught.TargetObject.SecretProfile | Should -Be ProtectedLab
        $caught.Exception.Message | Should -Not -Match DO_NOT_LEAK
        Test-Path $path | Should -BeFalse
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 0 -Exactly
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 0 -Exactly
    }
    It 'registration WhatIf returns before all preflight authentication enrollment and file I/O' {
        $path = Join-Path $TestDrive 'whatif.json'
        Register-GitHubPasskeyViaTAP -TAP (ConvertTo-SecureString 'synthetic-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -Repository owner/repo -ProtectedLab -Environment passkey-validation -RecoveryOutputPath $path -WhatIf
        Test-Path $path | Should -BeFalse
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 0 -Exactly
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 0 -Exactly
    }
    It 'registers through mocked auth and verified enrollment before exporting the same durable recovery credential' {
        $script:events = [Collections.Generic.List[string]]::new()
        Mock Invoke-GitHubPasskeyCli {
            if ($Arguments[0] -eq 'api') { $script:events.Add('preflight') }
            else {
                $script:events.Add($Arguments[2])
                $Arguments[-2] | Should -BeExactly '--env'
                $Arguments[-1] | Should -BeExactly 'passkey-validation'
                $saved = Get-Content $script:recoveryPath -Raw | ConvertFrom-Json
                $saved.credentialId | Should -BeExactly $script:fixture.credentialId
                if ($Arguments[2] -eq 'PASSKEY_LAB_PRIVATE_KEY') { $InputText | Should -BeExactly $saved.privateKey }
            }
        }
        Mock Invoke-EntraRegistrationTapAuthentication { $script:events.Add('authentication'); $Context }
        Mock Invoke-EntraSoftwareNativeRegistration {
            $script:events.Add('verified-enrollment')
            $record = [pscustomobject]$script:fixture.Clone()
            $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json))
            $CredentialOutputStream.Write($bytes, 0, $bytes.Length)
            $CredentialOutputStream.Flush($true)
            $Context.RecoveryOutputState = 'Durable'
            $Context.RecoveryOutputPath = $CredentialOutputPath
            $Context.RecoveryCredentialId = $record.credentialId
            $Context.EnrollmentStatus = 'Verified'
            [pscustomobject]@{ Credential = $record }
        }
        $script:recoveryPath = Join-Path $TestDrive 'registered.json'
        $result = Register-GitHubPasskeyViaTAP -TAP (ConvertTo-SecureString 'synthetic-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -Repository owner/repo -ProtectedLab -Environment passkey-validation -RecoveryOutputPath $script:recoveryPath -Confirm:$false
        $result.Success | Should -BeTrue
        $result.EnrollmentStatus | Should -BeExactly Verified
        $result.SecretProfile | Should -BeExactly ProtectedLab
        $result.RecoveryOutputPath | Should -BeExactly $script:recoveryPath
        $script:events -join ',' | Should -BeExactly ('preflight,preflight,authentication,verified-enrollment,preflight,preflight,' + ($script:names -join ','))
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 1 -Exactly
    }
    It 'retains verified recovery and reports no export when protections change after enrollment' {
        $script:checks = 0
        Mock Invoke-GitHubPasskeyCli {
            if ($Arguments[0] -eq 'api' -and ++$script:checks -eq 3) { throw 'SYNTHETIC_PROTECTION_REMOVED' }
        }
        Mock Invoke-EntraRegistrationTapAuthentication { $Context }
        Mock Invoke-EntraSoftwareNativeRegistration {
            $record = [pscustomobject]$script:fixture.Clone()
            $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json))
            $CredentialOutputStream.Write($bytes, 0, $bytes.Length); $CredentialOutputStream.Flush($true)
            $Context.RecoveryOutputState = 'Durable'; $Context.RecoveryOutputPath = $CredentialOutputPath
            $Context.RecoveryCredentialId = $record.credentialId; $Context.EnrollmentStatus = 'Verified'
            $Context.Stage = 'EnrollmentVerification'
            [pscustomobject]@{ Credential = $record }
        }
        $path = Join-Path $TestDrive 'protected-recovery.json'; $caught = $null
        try {
            Register-GitHubPasskeyViaTAP -TAP (ConvertTo-SecureString 'synthetic-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -Repository owner/repo -ProtectedLab -Environment passkey-validation -RecoveryOutputPath $path -Confirm:$false
        } catch { $caught = $_ }
        $caught.TargetObject.Stage | Should -BeExactly GitHubPreflight
        $caught.TargetObject.EnrollmentStatus | Should -BeExactly Verified
        $caught.TargetObject.ExportStatus | Should -BeExactly NotStarted
        $caught.TargetObject.RecoveryOutputPath | Should -BeExactly $path
        $caught.TargetObject.CredentialId | Should -BeExactly $script:fixture.credentialId
        $caught.Exception.Message | Should -Not -Match 'SYNTHETIC|BEGIN PRIVATE'
        (Get-Content $path -Raw | ConvertFrom-Json).privateKey | Should -BeExactly $script:fixture.privateKey
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'secret' }
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 1 -Exactly
    }
    It 'reports each partial lab write safely and retries the same credential without enrollment' -ForEach @(0,1,2,3) {
        $script:failAt = $_; $script:count = 0
        Mock Invoke-GitHubPasskeyCli {
            if ($Arguments[0] -eq 'secret' -and $script:count++ -eq $script:failAt) { throw 'DO_NOT_LEAK_PRIVATE_KEY' }
        }
        $caught = $null
        try { Export-PasskeyToGitHubSecret @script:arguments } catch { $caught = $_ }
        $caught.TargetObject.SecretProfile | Should -Be ProtectedLab
        $caught.TargetObject.ExportStatus | Should -Be Incomplete
        @($caught.TargetObject.ConfirmedWrites).Count | Should -Be $script:failAt
        $caught.TargetObject.FailedOrUnknownSecret | Should -BeExactly $script:names[$script:failAt]
        $caught.Exception.Message | Should -Not -Match 'DO_NOT_LEAK|BEGIN PRIVATE|fixture@'
        Mock Invoke-GitHubPasskeyCli {}
        $result = Export-PasskeyToGitHubSecret @script:arguments
        $result.Success | Should -BeTrue
        $result.SecretNames -join ',' | Should -BeExactly ($script:names -join ',')
        Should -Invoke Invoke-EntraRegistrationTapAuthentication -Times 0 -Exactly
        Should -Invoke Invoke-EntraSoftwareNativeRegistration -Times 0 -Exactly
    }
}
