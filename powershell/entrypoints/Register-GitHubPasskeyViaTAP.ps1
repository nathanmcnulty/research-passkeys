#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Unattended software implementation, not a FIDO-certified authenticator. Native packed attestation uses a synthetic self-signed batch certificate; any UP/UV claims are synthetic and provide no authenticator presence, verification or hardware assurance. Tenant policy may reject this flow. TenantId is optional: omitted values use validated UPN-suffix OIDC discovery; use an explicit GUID for a guest/resource tenant. Names must be nonblank and at most 30 characters. RecoveryOutputPath must name a new private credential file. The exact generated credential is durably saved before enrollment and retained after success, uncertain enrollment, verification failure, or partial GitHub export. WhatIf performs no I/O. GitHub export performs four non-atomic secret writes; pause or disable consumers yourself before continuing.
.PARAMETER RecoveryOutputPath
New caller-controlled path for the private recovery credential. Existing files are refused. Protect this file like the GitHub private-key secret; it remains after successful export so the same enrolled credential can be reconciled or exported again without another enrollment.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$RecoveryOutputPath,
        [ValidateLength(1,30)][string]$DisplayName = 'Software Passkey')
# Invoke public command
Register-GitHubPasskeyViaTAP @PSBoundParameters
