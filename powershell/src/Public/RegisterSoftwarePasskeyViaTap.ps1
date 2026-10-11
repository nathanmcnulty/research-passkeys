function Register-EntraSoftwarePasskeyViaTap {
    <# .SYNOPSIS
    Register a software passkey through the My Sign-ins TAP flow with packed attestation.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. Packed uses
    a synthetic self-signed batch certificate; UP/UV claims do not prove authenticator
    presence, verification or hardware assurance. WhatIf causes no I/O. Existing files are never overwritten.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][object]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [string]$OutputPath)
    if ($TenantId -eq [guid]::Empty -or $null -eq $TAP -or ($TAP -is [securestring] -and $TAP.Length -eq 0) -or
        ($TAP -is [string] -and [string]::IsNullOrWhiteSpace($TAP))) { throw 'TenantId and TAP cannot be empty.' }
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Enroll software passkey '$DisplayName' and save its private credential")) { return }
    Write-PasskeySoftwareWarning
    $context = $null; $stream = $null; $result = $null; $saved = $false
    try {
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName
        $stream = Open-EntraSoftwareCredentialOutput $path
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $DisplayName
        Write-EntraSoftwareCredentialOutput -Stream $stream -Credential $result.Credential
        $saved = $true
        [pscustomobject]@{ CredentialFilePath = $path; CredentialId = $result.Credential.credentialId; Success = $true }
    } catch { throw 'Software registration or persistence failed; sensitive details suppressed. Inspect My Sign-ins for a partially enrolled method before retrying. No rollback was attempted.' }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (-not $saved -and $null -ne $stream) { [IO.File]::Delete($path) }
        if ($null -ne $result) { $result.Credential.privateKey = $null }
        Clear-EntraRegistrationContext $context
    }
}
