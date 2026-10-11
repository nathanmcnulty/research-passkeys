function Register-GitHubPasskeyViaTAP {
    <# .SYNOPSIS
    Enroll a software passkey and export its verified record to four GitHub Actions secrets.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. Packed uses a synthetic
    self-signed batch certificate; UP/UV flags do not prove authenticator presence, verification or hardware assurance.
    ConsumersPaused acknowledges all consumers are already paused; four writes are not atomic.
    No plaintext credential file is created. WhatIf performs local validation only, with no I/O.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [switch]$ConsumersPaused)
    Assert-GitHubPasskeyRepository $Repository
    if ($TenantId -eq [guid]::Empty -or $TAP.Length -eq 0) { throw 'TenantId and TAP cannot be empty.' }
    if (-not $ConsumersPaused) { throw 'Pause consumers and supply -ConsumersPaused before enrollment.' }
    if (-not $PSCmdlet.ShouldProcess("Entra tenant $TenantId and github.com/$Repository", 'Enroll persistent software passkey and replace four repository secrets')) { return }
    Write-PasskeySoftwareWarning
    $context = $null; $result = $null; $exportStarted = $false
    try {
        Test-GitHubPasskeyDestination $Repository
        $context = New-EntraRegistrationContext
        $context = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        $result = Invoke-EntraSoftwareNativeRegistration -Context $context -DisplayName $DisplayName
        # The registration function returns only after exact credential-ID verification succeeded.
        $exportStarted = $true
        return Export-PasskeyToGitHubSecret -Credential $result.Credential -Repository $Repository -ConsumersPaused -Confirm:$false
    } catch {
        if ($exportStarted) { throw [InvalidOperationException]::new('Enrollment completed, but export did not finish. Keep consumers paused. ' + $_.Exception.Message) }
        throw [InvalidOperationException]::new('Registration failed; sensitive error details suppressed. A method may have been partially enrolled. Inspect My Sign-ins before retrying. No credential file was saved.')
    } finally {
        if ($null -ne $result) { $result.Credential.privateKey = $null; $result = $null }
        Clear-EntraRegistrationContext $context
    }
}
