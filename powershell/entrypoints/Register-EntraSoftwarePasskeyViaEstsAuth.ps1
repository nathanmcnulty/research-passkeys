#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Unattended software implementation, not a FIDO-certified authenticator. Native packed attestation uses a synthetic self-signed batch certificate; any UP/UV claims are synthetic and provide no authenticator presence, verification or hardware assurance. Tenant policy may reject this flow. WhatIf performs no I/O. Unix output uses 0600; Windows requires a private output directory because directory ACLs are inherited. GitHub export performs four non-atomic secret writes; pause or disable consumers yourself before continuing.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][object]$ESTSAuthCookie, [string]$TenantId,
        [Alias('DisplayName')][ValidateLength(1,30)][string]$PasskeyDisplayName = 'Software Passkey',
        [string]$OutputPath)
# Invoke public command
Register-EntraSoftwarePasskeyViaEstsAuth @PSBoundParameters
