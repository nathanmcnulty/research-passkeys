function Register-EntraSoftwarePasskeyViaEstsAuth {
    <# .SYNOPSIS
    Register a software passkey using an existing MFA ESTS session and packed attestation.
    .DESCRIPTION
    Resolves tenant and UPN from the transport-returned My Sign-ins token, checks OAuth state/client binding,
    and refuses consent interruptions. Unattended software implementation, not a FIDO-certified
    authenticator. Packed uses a synthetic self-signed batch certificate; UP/UV claims do not
    prove authenticator presence, verification or hardware assurance.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][object]$ESTSAuthCookie, [string]$TenantId,
        [Alias('DisplayName')][ValidateLength(1,30)][string]$PasskeyDisplayName = 'Software Passkey',
        [string]$OutputPath)
    if ($null -eq $ESTSAuthCookie -or ($ESTSAuthCookie -is [securestring] -and $ESTSAuthCookie.Length -eq 0) -or
        ($ESTSAuthCookie -is [string] -and [string]::IsNullOrWhiteSpace($ESTSAuthCookie))) { throw 'ESTSAuthCookie cannot be empty.' }
    if ($TenantId) {
        $tenant = [guid]::Empty
        if (-not [guid]::TryParse($TenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) { throw 'TenantId must be a nonempty GUID.' }
    }
    Assert-EntraPasskeyDisplayName $PasskeyDisplayName
    if (-not $PSCmdlet.ShouldProcess("ESTS session tenant $TenantId", "Enroll software passkey '$PasskeyDisplayName' and save its private credential")) { return }
    Write-PasskeySoftwareWarning
    $context = $null; $stream = $null; $result = $null; $saved = $false; $stage = 'CookieAuthentication'
    try {
        $context = New-EntraRegistrationContext
        $stage = 'CookieAuthentication'
        $context = Invoke-EntraRegistrationCookieAuthentication -Context $context -ESTSAuthCookie $ESTSAuthCookie -TenantId $TenantId
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $context.UserPrincipalName -DisplayName $PasskeyDisplayName
        $stage = 'OutputReservation'
        $stream = Open-EntraSoftwareCredentialOutput $path
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $PasskeyDisplayName
        $stage = 'CredentialPersistence'
        Write-EntraSoftwareCredentialOutput -Stream $stream -Credential $result.Credential
        $saved = $true
        [pscustomobject]@{ CredentialFilePath = $path; CredentialId = $result.Credential.credentialId; Success = $true }
    } catch {
        $enrollment = if ($null -ne $result) { 'Verified' } elseif ($context -and $context.EnrollmentStatus) { $context.EnrollmentStatus } else { 'NotStarted' }
        if ($stage -ne 'CredentialPersistence' -and $context -and $context.Stage -and $context.Stage -ne 'NotStarted') { $stage = $context.Stage }
        $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage $stage -EnrollmentStatus $enrollment))
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (-not $saved -and $null -ne $stream) { [IO.File]::Delete($path) }
        if ($null -ne $result) { $result.Credential.privateKey = $null }
        Clear-EntraRegistrationContext $context
    }
}
