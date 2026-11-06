BeforeAll {
    $script:Repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $manifest = Import-PowerShellDataFile "$script:Repo/build/targets.psd1"
    $sources = ($manifest.Scripts | Where-Object Path -EQ 'powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1').Sources
    foreach ($source in $sources) { . "$script:Repo/$source" }
    # Faults are injected into the real writer/Flush(true), without any network or provider calls.
    if (-not ('PasskeyTests.FaultingCredentialStream' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
namespace PasskeyTests {
    public class FaultingCredentialStream : FileStream {
        public string Fault;
        public bool Durable;
        public FaultingCredentialStream(string path, string fault)
            : base(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None) { Fault = fault; }
        public override void Write(byte[] buffer, int offset, int count) {
            if (Fault == "Write") {
                base.Write(buffer, offset, Math.Min(count, 20));
                throw new IOException("SYNTHETIC-PRIVATE-WRITE-DETAIL");
            }
            base.Write(buffer, offset, count);
        }
        public override void Flush(bool flushToDisk) {
            if (Fault == "Flush") { throw new IOException("SYNTHETIC-PRIVATE-FLUSH-DETAIL"); }
            base.Flush(flushToDisk);
            if (flushToDisk) { Durable = true; }
        }
    }
}
'@
    }
}

Describe 'Graph enrollment recovery boundary' {
    BeforeEach {
        $script:Path = Join-Path $TestDrive "$([guid]::NewGuid().ToString('N')).json"
        $script:Fault = ''
        $script:Stream = $null
        $script:Record = [ordered]@{ credentialId = 'AQIDBA'; privateKey = 'SYNTHETIC-PRIVATE-KEY'; userHandle = 'BQYHCA' }
        Mock Invoke-RestMethod { throw 'Unexpected network call' }
        Mock Invoke-WebRequest { throw 'Unexpected network call' }
        Mock Resolve-EntraSoftwareGraphTenant { '11111111-1111-4111-8111-111111111111' }
        Mock Get-EntraSoftwareApplicationToken { 'SYNTHETIC-ACCESS-TOKEN' }
        Mock Get-EntraSoftwareGraphCreationOptions { @{ challenge = 'AQID'; user = @{ id = 'BAUG'; name = 'fixture@example.invalid' } } }
        Mock New-SoftwarePasskeyKey { [pscustomobject]@{ Key = $null; PrivateKeyPem = 'SYNTHETIC-PRIVATE-KEY' } }
        Mock New-EntraSoftwareAttestation { [pscustomobject]@{ CredentialId = 'AQIDBA' } }
        Mock New-EntraSoftwareCredentialRecord { $script:Record }
        Mock Clear-SoftwarePasskeyKey {}
        Mock Open-EntraSoftwareCredentialOutput {
            $script:Stream = [PasskeyTests.FaultingCredentialStream]::new($OutputPath, $script:Fault)
            $script:Stream
        }
        Mock Submit-EntraSoftwareGraphRegistration {
            $script:Stream.Durable | Should -BeTrue -Because 'the real writer must flush to disk before enrollment'
            $script:Stream.Position = 0
            $reader = [IO.StreamReader]::new($script:Stream, [Text.Encoding]::UTF8, $false, 1024, $true)
            try { $saved = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
            $saved.credentialId | Should -BeExactly $script:Record.credentialId
            $saved.privateKey | Should -BeExactly $script:Record.privateKey
            @{ id = 'synthetic-method'; displayName = 'Recovery fixture' }
        }
        $script:Parameters = @{ UserUpn = 'fixture@example.invalid'; DisplayName = 'Recovery fixture';
            UseManagedIdentity = $true; OutputPath = $script:Path; Confirm = $false }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'durably persists the exact credential before confirmed enrollment' {
        $result = Register-EntraSoftwarePasskey @script:Parameters
        $result.Success | Should -BeTrue
        $result.MethodId | Should -BeExactly 'synthetic-method'
        (Get-Content $script:Path -Raw | ConvertFrom-Json).privateKey | Should -BeExactly 'SYNTHETIC-PRIVATE-KEY'
        Should -Invoke Submit-EntraSoftwareGraphRegistration -Times 1 -Exactly
    }
    It 'retains recovery evidence and never submits when <Fault> fails' -ForEach @(@{ Fault = 'Write' }, @{ Fault = 'Flush' }) {
        $script:Fault = $Fault
        $caught = $null
        try { Register-EntraSoftwarePasskey @script:Parameters } catch { $caught = $_ }
        $caught.TargetObject.Stage | Should -BeExactly 'CredentialPersistence'
        $caught.TargetObject.EnrollmentStatus | Should -BeExactly 'NotStarted'
        $caught.TargetObject.RecoveryOutputPath | Should -BeExactly $script:Path
        $caught.TargetObject.CredentialId | Should -BeExactly 'AQIDBA'
        $caught.Exception.Message | Should -Not -Match 'SYNTHETIC|PRIVATE'
        (Get-Item $script:Path).Length | Should -BeGreaterThan 0
        if ($Fault -eq 'Flush') { (Get-Content $script:Path -Raw | ConvertFrom-Json).privateKey | Should -BeExactly 'SYNTHETIC-PRIVATE-KEY' }
        Should -Invoke Submit-EntraSoftwareGraphRegistration -Times 0 -Exactly
    }
    It 'retains the durable credential after an uncertain submission and suppresses transport details' {
        Mock Submit-EntraSoftwareGraphRegistration { throw 'SYNTHETIC-PRIVATE-SERVER-DETAIL' }
        $caught = $null
        try { Register-EntraSoftwarePasskey @script:Parameters } catch { $caught = $_ }
        $caught.TargetObject.Stage | Should -BeExactly 'CredentialSubmission'
        $caught.TargetObject.EnrollmentStatus | Should -BeExactly 'Unconfirmed'
        $caught.TargetObject.RecoveryOutputPath | Should -BeExactly $script:Path
        $caught.TargetObject.CredentialId | Should -BeExactly 'AQIDBA'
        $caught.Exception.Message | Should -Not -Match 'SYNTHETIC|PRIVATE'
        (Get-Content $script:Path -Raw | ConvertFrom-Json).privateKey | Should -BeExactly 'SYNTHETIC-PRIVATE-KEY'
        Should -Invoke Submit-EntraSoftwareGraphRegistration -Times 1 -Exactly
    }
    It 'removes only its empty reservation when preparation fails before writing' {
        Mock Get-EntraSoftwareGraphCreationOptions { throw 'SYNTHETIC-PRIVATE-OPTIONS-DETAIL' }
        { Register-EntraSoftwarePasskey @script:Parameters } | Should -Throw '*RegistrationOptions*'
        Test-Path $script:Path | Should -BeFalse
        Should -Invoke Submit-EntraSoftwareGraphRegistration -Times 0 -Exactly
    }
    It 'does not change an existing file or start authentication when exclusive reservation fails' {
        [IO.File]::WriteAllText($script:Path, 'existing private record')
        { Register-EntraSoftwarePasskey @script:Parameters } | Should -Throw '*OutputReservation*'
        [IO.File]::ReadAllText($script:Path) | Should -BeExactly 'existing private record'
        Should -Invoke Get-EntraSoftwareApplicationToken -Times 0 -Exactly
        Should -Invoke Submit-EntraSoftwareGraphRegistration -Times 0 -Exactly
    }
}

Describe 'Credential output follows PowerShell filesystem location' {
    BeforeEach {
        $script:OriginalLocation = Get-Location
        $script:OriginalProcessDirectory = [Environment]::CurrentDirectory
        $script:RunspaceDirectory = Join-Path $TestDrive 'runspace'
        $script:ProcessDirectory = Join-Path $TestDrive 'process'
        $null = [IO.Directory]::CreateDirectory($script:RunspaceDirectory)
        $null = [IO.Directory]::CreateDirectory($script:ProcessDirectory)
        $null = [IO.Directory]::CreateDirectory((Join-Path $script:RunspaceDirectory 'private'))
        [Environment]::CurrentDirectory = $script:ProcessDirectory
        Set-Location $script:RunspaceDirectory
    }
    AfterEach {
        Set-Location $script:OriginalLocation
        [Environment]::CurrentDirectory = $script:OriginalProcessDirectory
    }
    It 'resolves default, relative file and relative directory paths from the runspace' {
        $arguments = @{ UserPrincipalName = 'fixture@example.invalid'; DisplayName = 'Sample' }
        Resolve-EntraSoftwareOutputPath @arguments | Should -BeExactly (Join-Path $script:RunspaceDirectory 'fixture_Sample_credential.json')
        Resolve-EntraSoftwareOutputPath @arguments -OutputPath './private/recovery.json' | Should -BeExactly (Join-Path $script:RunspaceDirectory 'private/recovery.json')
        Resolve-EntraSoftwareOutputPath @arguments -OutputPath './private' | Should -BeExactly (Join-Path $script:RunspaceDirectory 'private/fixture_Sample_credential.json')
    }
    It 'preserves an explicitly absolute filesystem path' {
        $absolute = Join-Path $script:ProcessDirectory 'explicit.json'
        Resolve-EntraSoftwareOutputPath -OutputPath $absolute -UserPrincipalName 'fixture@example.invalid' -DisplayName Sample | Should -BeExactly $absolute
    }
    It 'rejects non-filesystem providers without creating a credential' {
        { Resolve-EntraSoftwareOutputPath -OutputPath 'Env:PASSKEY_TEST_CREDENTIAL' -UserPrincipalName 'fixture@example.invalid' -DisplayName Sample } | Should -Throw '*filesystem*'
    }
}
