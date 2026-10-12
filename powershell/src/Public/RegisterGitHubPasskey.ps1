function Register-GitHubPasskeyViaTAP {
    <# .SYNOPSIS
    Enroll a software passkey and export its verified record to four GitHub Actions secrets.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. Packed uses a synthetic
    self-signed batch certificate; UP/UV flags do not prove authenticator presence, verification or hardware assurance.
    Four writes are not atomic. Pause consumers yourself; this command does not pause them.
    No plaintext credential file is created. WhatIf performs local validation only, with no I/O.
    TenantId overrides UPN-suffix discovery, including guest/resource-tenant scenarios.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey')
    Assert-GitHubPasskeyRepository $Repository
    Assert-EntraPasskeyDisplayName $DisplayName
    if ($TAP.Length -eq 0) { throw 'TAP cannot be empty.' }
    if ($TenantId) { $null = Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserPrincipalName }
    if (-not $PSCmdlet.ShouldProcess("$UserPrincipalName in Entra and github.com/$Repository", 'Enroll persistent software passkey and replace four repository secrets')) { return }
    Write-PasskeySoftwareWarning
    Write-GitHubPasskeyExportWarning
    $context = $null; $result = $null; $stage = 'GitHubPreflight'
    try {
        Test-GitHubPasskeyDestination $Repository
        $stage = 'TenantDiscovery'
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $DisplayName
        # Only exact credential-ID verification permits export. No second enrollment or rollback.
        $stage = 'GitHubExport'
        return Invoke-GitHubPasskeySecretExport -Values (Get-GitHubPasskeySecretValues $result.Credential) -Repository $Repository -EnrollmentStatus Verified
    } catch {
        # Exporter errors are locally constructed, secret-free records; preserve write accounting.
        if ($_.FullyQualifiedErrorId -like 'PasskeyGitHubExportFailed,*') { $PSCmdlet.ThrowTerminatingError($_) }
        $enrollment = if ($null -ne $result) { 'Verified' } elseif ($context -and $context.EnrollmentStatus) { $context.EnrollmentStatus } else { 'NotStarted' }
        if ($stage -ne 'GitHubExport' -and $context -and $context.Stage -and $context.Stage -ne 'NotStarted') { $stage = $context.Stage }
        $export = if ($stage -eq 'GitHubExport') { 'Incomplete' } else { 'NotStarted' }
        $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage $stage -EnrollmentStatus $enrollment -ExportStatus $export -AuthorizationFailure $(if ($context) { $context.AuthorizationFailure })))
    } finally {
        if ($null -ne $result) { $result.Credential.privateKey = $null; $result = $null }
        Clear-EntraRegistrationContext $context
    }
}
