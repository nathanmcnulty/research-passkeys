#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Unattended software implementation, not a FIDO-certified authenticator. Native packed attestation uses a synthetic self-signed batch certificate; any UP/UV claims are synthetic and provide no authenticator presence, verification or hardware assurance. Tenant policy may reject this flow. The exact generated private credential is durably written to OutputPath before credential submission. The file is retained after confirmed or uncertain enrollment and its path and credential ID are reported on failure for reconciliation before another enrollment. WhatIf performs no I/O. Unix output uses 0600; Windows requires a private output directory because directory ACLs are inherited.
.PARAMETER OutputPath
New private credential file or an existing output directory. Existing files are refused. If omitted, a new file is created in the current directory after the authenticated identity is resolved.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][object]$ESTSAuthCookie, [string]$TenantId,
        [Alias('DisplayName')][ValidateLength(1,30)][string]$PasskeyDisplayName = 'Software Passkey',
        [string]$OutputPath)
# Invoke public command
Register-EntraSoftwarePasskeyViaEstsAuth @PSBoundParameters
