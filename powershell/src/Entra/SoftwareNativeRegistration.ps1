function Invoke-EntraSoftwareNativeRegistration {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][IO.FileStream]$CredentialOutputStream,
        [Parameter(Mandatory)][string]$CredentialOutputPath)
    $provider = $null
    try {
        $Context.Stage = 'SessionAuthorization'
        $Context = Initialize-EntraRegistrationSession -Context $Context
        $Context.Stage = 'RegistrationOptions'
        $request = Initialize-EntraRegistrationRequest -Context $Context
        $Context.Stage = 'Attestation'
        $provider = New-SoftwarePasskeyKey
        $attestation = New-EntraSoftwareAttestation -Provider $provider -Challenge $request.ServerChallenge -Format Packed
        $Context.Stage = 'CredentialPersistence'
        $record = New-EntraSoftwareCredentialRecord -Provider $provider -Attestation $attestation -UserHandle $request.UserHandle `
            -UserPrincipalName $Context.UserPrincipalName -DisplayName $DisplayName
        $Context.RecoveryOutputPath = $CredentialOutputPath
        $Context.RecoveryCredentialId = $attestation.CredentialId
        # Retain even a partial write as recovery evidence. No enrollment request has been
        # submitted yet, and a persistence failure stops the operation at this boundary.
        $Context.RecoveryOutputState = 'WriteAttempted'
        Write-EntraSoftwareCredentialOutput -Stream $CredentialOutputStream -Credential $record
        $Context.RecoveryOutputState = 'Durable'
        $verified = Submit-EntraRegistration -Context $Context -Request $request -Attestation $attestation -DisplayName $DisplayName
        $Context.EnrollmentStatus = 'Verified'
        return [pscustomobject]@{ Credential = $record; Verification = $verified; TenantId = $Context.TenantId; UserPrincipalName = $Context.UserPrincipalName }
    } finally { Clear-SoftwarePasskeyKey $provider }
}
