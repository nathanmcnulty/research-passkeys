#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Unattended software implementation, not a FIDO-certified authenticator. Native packed attestation uses a synthetic self-signed batch certificate; any UP/UV claims are synthetic and provide no authenticator presence, verification or hardware assurance. Tenant policy may reject this flow. TenantId is optional: omitted values use validated UPN-suffix OIDC discovery; use an explicit GUID for a guest/resource tenant. Names must be nonblank and at most 30 characters. WhatIf performs no I/O. GitHub export performs four non-atomic secret writes; pause or disable consumers yourself before continuing.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey')
# Invoke public command
Register-GitHubPasskeyViaTAP @PSBoundParameters
