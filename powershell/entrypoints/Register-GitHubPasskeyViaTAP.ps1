#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Unattended software implementation, not a FIDO-certified authenticator. Native packed attestation uses a synthetic self-signed batch certificate; any UP/UV claims are synthetic and provide no authenticator presence, verification or hardware assurance. Tenant policy may reject this flow. WhatIf performs no I/O. GitHub export requires ConsumersPaused and four non-atomic secret writes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [switch]$ConsumersPaused)
# Invoke public command
Register-GitHubPasskeyViaTAP @PSBoundParameters
