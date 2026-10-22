function Register-EntraSoftwarePasskeyViaTap {
    <# .SYNOPSIS
    Register a software passkey through the My Sign-ins TAP flow with packed attestation.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. Packed uses
    a synthetic self-signed batch certificate; UP/UV claims do not prove authenticator
    presence, verification or hardware assurance. The private credential is durably written
    before submission and retained for reconciliation after uncertain enrollment. WhatIf causes
    no I/O. Existing files are never overwritten.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][object]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId, [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey',
        [string]$OutputPath)
    if ($null -eq $TAP -or ($TAP -is [securestring] -and $TAP.Length -eq 0) -or
        ($TAP -is [string] -and [string]::IsNullOrWhiteSpace($TAP))) { throw 'TAP cannot be empty.' }
    Assert-EntraPasskeyDisplayName $DisplayName
    if ($TenantId) { $null = Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserPrincipalName }
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Enroll software passkey '$DisplayName' and save its private credential")) { return }
    Write-PasskeySoftwareWarning
    $context = $null; $stream = $null; $result = $null; $saved = $false; $stage = 'OutputReservation'
    try {
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName
        $stage = 'OutputReservation'
        $stream = Open-EntraSoftwareCredentialOutput $path
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $DisplayName `
            -CredentialOutputStream $stream -CredentialOutputPath $path
        $saved = $true
        [pscustomobject]@{ CredentialFilePath = $path; CredentialId = $result.Credential.credentialId; Success = $true }
    } catch {
        $enrollment = if ($null -ne $result) { 'Verified' } elseif ($context -and $context.EnrollmentStatus) { $context.EnrollmentStatus } else { 'NotStarted' }
        if ($stage -ne 'CredentialPersistence' -and $context -and $context.Stage -and $context.Stage -ne 'NotStarted') { $stage = $context.Stage }
        $hasRecovery = $context -and $context.PSObject.Properties['RecoveryOutputState'] -and
            $context.RecoveryOutputState -in @('WriteAttempted','Durable')
        $recovery = if ($hasRecovery) { $context.RecoveryOutputPath } else { $null }
        $credentialId = if ($hasRecovery) { $context.RecoveryCredentialId } else { $null }
        $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage $stage -EnrollmentStatus $enrollment `
            -RecoveryOutputPath $recovery -CredentialId $credentialId -AuthorizationFailure $(if ($context) { $context.AuthorizationFailure })))
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $retain = $context -and $context.PSObject.Properties['RecoveryOutputState'] -and
            $context.RecoveryOutputState -in @('WriteAttempted','Durable')
        if (-not $saved -and $null -ne $stream -and -not $retain) { [IO.File]::Delete($path) }
        if ($null -ne $result) { $result.Credential.privateKey = $null }
        Clear-EntraRegistrationContext $context
    }
}
