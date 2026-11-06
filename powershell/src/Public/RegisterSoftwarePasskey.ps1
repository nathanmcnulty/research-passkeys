function Register-EntraSoftwarePasskey {
    <# .SYNOPSIS
    Register a research software passkey using Graph application permissions and none attestation.
    .DESCRIPTION
    Supports local P-256 keys or a Key Vault reference. Unattended software implementation,
    not a FIDO-certified authenticator. Synthetic UP/UV claims do not establish authenticator
    presence, verification or hardware assurance. Graph uses none attestation.
    The credential record is durably saved before enrollment and retained after a write attempt
    or uncertain submission. Existing files are never silently overwritten.
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
        $path = $null; $stream = $null; $result = $null
        $context = [pscustomobject]@{ Stage = 'OutputReservation'; EnrollmentStatus = 'NotStarted'
            RecoveryOutputPath = $null; RecoveryCredentialId = $null; RecoveryOutputState = 'NotStarted' }
        try {
            $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $UserUpn -DisplayName $DisplayName
            $stream = Open-EntraSoftwareCredentialOutput -OutputPath $path
            $result = Invoke-EntraSoftwareGraphRegistration -UserUpn $UserUpn -DisplayName $DisplayName `
                -Authentication (Get-EntraSoftwareAuthenticationParameters $configuration) `
                -UseKeyVault:$configuration.UseKeyVault -KeyVaultName $configuration.KeyVaultName `
                -Context $context -CredentialOutputStream $stream -CredentialOutputPath $path
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
            $retain = $context.RecoveryOutputState -in @('WriteAttempted','Durable')
            $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage $context.Stage `
                -EnrollmentStatus $context.EnrollmentStatus `
                -RecoveryOutputPath $(if ($retain) { $context.RecoveryOutputPath }) `
                -CredentialId $(if ($retain) { $context.RecoveryCredentialId })))
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
            $retain = $context.RecoveryOutputState -in @('WriteAttempted','Durable')
            # Only delete this invocation's empty reservation before any write attempt.
            if ($null -ne $stream -and -not $retain) { [IO.File]::Delete($path) }
            if ($null -ne $result -and $result.Credential.Contains('privateKey')) { $result.Credential.privateKey = $null }
            $configuration.ClientSecret = $null
        }
    }
}
