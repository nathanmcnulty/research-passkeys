#Requires -Version 7.6

<# .SYNOPSIS
Experimentally enroll a legacy software passkey through native My Sign-ins endpoints.
.DESCRIPTION
Requires AllowLegacySoftwareAttestation acknowledgement. Packed software attestation and UP/UV claims are not trusted assurance. WhatIf performs no I/O. GitHub export requires ConsumersPaused and four non-atomic secret writes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][securestring]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [Parameter(Mandatory)][guid]$TenantId, [Parameter(Mandatory)][string]$Repository,
        [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [switch]$ConsumersPaused, [switch]$AllowLegacySoftwareAttestation)
# Invoke public command
Register-GitHubPasskeyViaTAP @PSBoundParameters
