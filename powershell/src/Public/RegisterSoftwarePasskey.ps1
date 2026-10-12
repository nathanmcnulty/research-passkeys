function Register-EntraSoftwarePasskey {
    <# .SYNOPSIS
    Register a research software passkey using Graph application permissions and none attestation.
    .DESCRIPTION
    Supports local P-256 keys or a Key Vault reference. Unattended software implementation,
    not a FIDO-certified authenticator. Synthetic UP/UV claims do not establish authenticator
    presence, verification or hardware assurance. Graph uses none attestation.
    The private-key output is reserved before registration and never silently overwritten.
    WhatIf performs local parameter validation only. Explicit PassThru forwards application configuration
    with ClientSecret kept as SecureString, never plaintext.
    Unix output is created mode 0600; Windows inherits directory ACLs and requires a private output directory.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ClientSecret', SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(ValueFromPipeline)][pscustomobject]$ConfigFromPipeline,
        [Parameter(Mandatory)][string]$UserUpn, [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey',
        [Parameter(ParameterSetName = 'ClientSecret')][Parameter(ParameterSetName = 'Certificate')][string]$ClientId,
        [Parameter(ParameterSetName = 'ClientSecret')][securestring]$ClientSecret,
        [Parameter(ParameterSetName = 'Certificate')][string]$ClientCertificatePath,
        [Parameter(ParameterSetName = 'Certificate')][securestring]$ClientCertificatePassword,
        [Parameter(ParameterSetName = 'ManagedIdentity')][switch]$UseManagedIdentity,
        [string]$OutputPath, [switch]$UseKeyVault, [string]$KeyVaultName, [string]$TenantId, [switch]$PassThru)
    process {
        $configuration = Resolve-EntraSoftwareConfiguration -Parameters (@{} + $PSBoundParameters) `
            -ConfigFromPipeline $ConfigFromPipeline -ParameterSetName $PSCmdlet.ParameterSetName
        # Defaults absent from PSBoundParameters are still explicit workflow inputs.
        $configuration.DisplayName = $DisplayName
        Assert-EntraPasskeyDisplayName $DisplayName
        if (-not $PSCmdlet.ShouldProcess($UserUpn, "Register software passkey '$DisplayName' and save its credential record")) { return }
        Write-PasskeySoftwareWarning
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $UserUpn -DisplayName $DisplayName
        $stream = $null; $result = $null; $saved = $false
        try {
            $stream = Open-EntraSoftwareCredentialOutput -OutputPath $path
            $result = Invoke-EntraSoftwareGraphRegistration -UserUpn $UserUpn -DisplayName $DisplayName `
                -Authentication (Get-EntraSoftwareAuthenticationParameters $configuration) `
                -UseKeyVault:$configuration.UseKeyVault -KeyVaultName $configuration.KeyVaultName
            Write-EntraSoftwareCredentialOutput -Stream $stream -Credential $result.Credential
            $saved = $true
            if ($PassThru) {
                $output = [pscustomobject]@{ CredentialFilePath = $path; UserUpn = $UserUpn; DisplayName = $DisplayName
                    TenantId = $result.TenantId; UsesKeyVault = [bool]$configuration.UseKeyVault
                    KeyVaultName = $configuration.KeyVaultName; ClientId = $configuration.ClientId
                    KeyName = if ($configuration.UseKeyVault) { $result.Credential.keyVault.keyName } else { $null }
                    MethodId = $result.Method.id; RegistrationTime = [DateTimeOffset]::UtcNow }
                if ($configuration.ClientSecret) {
                    $output | Add-Member -NotePropertyName ClientSecret -NotePropertyValue $configuration.ClientSecret
                }
                $output
            } else { [pscustomobject]@{ CredentialFilePath = $path; MethodId = $result.Method.id; Success = $true } }
        } catch {
            if ($null -ne $result) { throw 'Registration completed but credential persistence failed. Inspect the newly created method; no rollback was attempted.' }
            throw 'Software registration failed; sensitive response details suppressed. Inspect Entra for a partially created method or Key Vault key before retrying.'
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
            if (-not $saved -and $null -ne $stream) { [IO.File]::Delete($path) }
            if ($null -ne $result -and $result.Credential.Contains('privateKey')) { $result.Credential.privateKey = $null }
            $configuration.ClientSecret = $null
        }
    }
}
