function Invoke-EntraSoftwareNativeRegistration {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$DisplayName)
    $provider = $null
    try {
        $Context.Stage = 'SessionAuthorization'
        $Context = Initialize-EntraRegistrationSession -Context $Context
        $Context.Stage = 'RegistrationOptions'
        $request = Initialize-EntraRegistrationRequest -Context $Context
        $Context.Stage = 'Attestation'
        $provider = New-SoftwarePasskeyKey
        $attestation = New-EntraSoftwareAttestation -Provider $provider -Challenge $request.ServerChallenge -Format Packed
        $verified = Submit-EntraRegistration -Context $Context -Request $request -Attestation $attestation -DisplayName $DisplayName
        $Context.Stage = 'CredentialRecord'
        $Context.EnrollmentStatus = 'Verified'
        $record = New-EntraSoftwareCredentialRecord -Provider $provider -Attestation $attestation -UserHandle $request.UserHandle `
            -UserPrincipalName $Context.UserPrincipalName -DisplayName $DisplayName
        return [pscustomobject]@{ Credential = $record; Verification = $verified; TenantId = $Context.TenantId; UserPrincipalName = $Context.UserPrincipalName }
    } finally { Clear-SoftwarePasskeyKey $provider }
}
