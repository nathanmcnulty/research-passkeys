function Register-GitHubPasskeyViaTAP {
    <# .SYNOPSIS
    Enroll a software passkey and export its verified record to four GitHub Actions secrets.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. Packed uses a synthetic
    self-signed batch certificate; UP/UV flags do not prove authenticator presence, verification or hardware assurance.
    Four writes are not atomic. Pause consumers yourself; this command does not pause them.
    RecoveryOutputPath is an exclusive private credential file. It is durably written before
    enrollment and retained after success or any failure that may have created a method.
    WhatIf performs local validation only, with no I/O.
    TenantId overrides UPN-suffix discovery, including guest/resource-tenant scenarios.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$RecoveryOutputPath,
        [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey')
    Assert-GitHubPasskeyRepository $Repository
    Assert-EntraPasskeyDisplayName $DisplayName
    if ($TAP.Length -eq 0) { throw 'TAP cannot be empty.' }
    if ($TenantId) { $null = Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserPrincipalName }
    if (-not $PSCmdlet.ShouldProcess("$UserPrincipalName in Entra, github.com/$Repository, and $RecoveryOutputPath", 'Create a durable private recovery file, enroll a persistent software passkey, and replace four repository secrets')) { return }
    Write-PasskeySoftwareWarning
    Write-GitHubPasskeyExportWarning
    $context = $null; $result = $null; $stream = $null; $reserved = $false; $saved = $false; $path = $null; $stage = 'GitHubPreflight'
    try {
        Test-GitHubPasskeyDestination $Repository
        $path = Resolve-EntraSoftwareOutputPath -OutputPath $RecoveryOutputPath -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName
        $stage = 'OutputReservation'
        $stream = Open-EntraSoftwareCredentialOutput -OutputPath $path
        $reserved = $true
        $stage = 'TenantDiscovery'
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $DisplayName `
            -CredentialOutputStream $stream -CredentialOutputPath $path
        $saved = $true
        $stream.Dispose(); $stream = $null
        # Only exact credential-ID verification permits export. No second enrollment or rollback.
        $stage = 'GitHubExport'
        $export = Invoke-GitHubPasskeySecretExport -Values (Get-GitHubPasskeySecretValues $result.Credential) -Repository $Repository -EnrollmentStatus Verified
        $export | Add-Member -NotePropertyName RecoveryOutputPath -NotePropertyValue $path
        $export | Add-Member -NotePropertyName CredentialId -NotePropertyValue $result.Credential.credentialId
        return $export
    } catch {
        $enrollment = if ($null -ne $result) { 'Verified' } elseif ($context -and $context.EnrollmentStatus) { $context.EnrollmentStatus } else { 'NotStarted' }
        if ($stage -ne 'GitHubExport' -and $context -and $context.Stage -and $context.Stage -ne 'NotStarted') { $stage = $context.Stage }
        $export = if ($stage -eq 'GitHubExport') { 'Incomplete' } else { 'NotStarted' }
        $hasRecovery = $context -and $context.PSObject.Properties['RecoveryOutputState'] -and
            $context.RecoveryOutputState -in @('WriteAttempted','Durable')
        $recovery = if ($hasRecovery) { $context.RecoveryOutputPath } else { $null }
        $credentialId = if ($hasRecovery) { $context.RecoveryCredentialId } else { $null }
        if ($_.FullyQualifiedErrorId -like 'PasskeyGitHubExportFailed,*') {
            $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage GitHubExport -EnrollmentStatus Verified -ExportStatus Incomplete `
                -ConfirmedWrites @($_.TargetObject.ConfirmedWrites) -FailedOrUnknownSecret $_.TargetObject.FailedOrUnknownSecret `
                -RecoveryOutputPath $recovery -CredentialId $credentialId -CliFailure $_.TargetObject))
        }
        $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage $stage -EnrollmentStatus $enrollment -ExportStatus $export `
            -RecoveryOutputPath $recovery -CredentialId $credentialId -AuthorizationFailure $(if ($context) { $context.AuthorizationFailure }) -CliFailure $_.TargetObject))
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $retain = $context -and $context.PSObject.Properties['RecoveryOutputState'] -and
            $context.RecoveryOutputState -in @('WriteAttempted','Durable')
        if ($reserved -and -not $saved -and -not $retain) { [IO.File]::Delete($path) }
        if ($null -ne $result) { $result.Credential.privateKey = $null; $result = $null }
        Clear-EntraRegistrationContext $context
    }
}
