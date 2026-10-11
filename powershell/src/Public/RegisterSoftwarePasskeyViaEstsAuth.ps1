function Register-EntraSoftwarePasskeyViaEstsAuth {
    <# .SYNOPSIS
    Experimentally register a legacy packed software passkey using an existing MFA ESTS session.
    .DESCRIPTION
    Resolves tenant and UPN from the transport-returned My Sign-ins token, checks OAuth state/client binding,
    and refuses consent interruptions. Synthetic software UP/UV claims are not trusted assurance.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][object]$ESTSAuthCookie, [string]$TenantId,
        [Alias('DisplayName')][ValidateLength(1,100)][string]$PasskeyDisplayName = 'Software Passkey',
        [string]$OutputPath, [switch]$AllowLegacySoftwareAttestation)
    if ($null -eq $ESTSAuthCookie -or ($ESTSAuthCookie -is [securestring] -and $ESTSAuthCookie.Length -eq 0) -or
        ($ESTSAuthCookie -is [string] -and [string]::IsNullOrWhiteSpace($ESTSAuthCookie))) { throw 'ESTSAuthCookie cannot be empty.' }
    if ($TenantId) {
        $tenant = [guid]::Empty
        if (-not [guid]::TryParse($TenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) { throw 'TenantId must be a nonempty GUID.' }
    }
    if (-not $AllowLegacySoftwareAttestation) { throw 'This experimental flow requires -AllowLegacySoftwareAttestation acknowledgement.' }
    if (-not $PSCmdlet.ShouldProcess("ESTS session tenant $TenantId", "Enroll legacy software passkey '$PasskeyDisplayName' and save its private credential")) { return }
    $context = $null; $stream = $null; $result = $null; $saved = $false
    try {
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationCookieAuthentication -Context $context -ESTSAuthCookie $ESTSAuthCookie -TenantId $TenantId
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $OutputPath -UserPrincipalName $context.UserPrincipalName -DisplayName $PasskeyDisplayName
        $stream = Open-EntraSoftwareCredentialOutput $path
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $PasskeyDisplayName
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
