function Register-EntraSoftwarePasskeyViaTap {
    <# .SYNOPSIS
    Experimentally register a legacy packed software passkey through the My Sign-ins TAP flow.
    .DESCRIPTION
    Requires acknowledgement of synthetic software attestation and unsupported native endpoints.
    UP/UV claims are not trusted assurance. WhatIf causes no I/O. Existing output files are never overwritten.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][object]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [string]$OutputPath, [switch]$AllowLegacySoftwareAttestation)
    if ($TenantId -eq [guid]::Empty -or $null -eq $TAP -or ($TAP -is [securestring] -and $TAP.Length -eq 0) -or
        ($TAP -is [string] -and [string]::IsNullOrWhiteSpace($TAP))) { throw 'TenantId and TAP cannot be empty.' }
    if (-not $AllowLegacySoftwareAttestation) { throw 'This experimental flow requires -AllowLegacySoftwareAttestation acknowledgement.' }
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Enroll legacy software passkey '$DisplayName' and save its private credential")) { return }
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
