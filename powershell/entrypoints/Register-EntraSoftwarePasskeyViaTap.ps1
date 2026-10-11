#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Requires AllowLegacySoftwareAttestation acknowledgement. Packed software attestation and UP/UV claims are not trusted assurance. WhatIf performs no I/O. Unix output uses 0600; Windows requires a private output directory because directory ACLs are inherited. GitHub export requires ConsumersPaused and four non-atomic secret writes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][object]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [string]$OutputPath, [switch]$AllowLegacySoftwareAttestation)
# Invoke public command
Register-EntraSoftwarePasskeyViaTap @PSBoundParameters
