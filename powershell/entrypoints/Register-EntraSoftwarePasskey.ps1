#Requires -Version 7.6

<# .SYNOPSIS
Register a research Entra software passkey with Graph application authentication and none attestation.
.DESCRIPTION
Synthetic software UP/UV claims do not establish trusted assurance. Output files are never silently overwritten. Explicit PassThru forwards application configuration with ClientSecret kept as SecureString, never plaintext. Unix files use 0600; Windows requires a private directory because directory ACLs are inherited. WhatIf performs no I/O.
#>
[CmdletBinding(DefaultParameterSetName = 'ClientSecret', SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(ValueFromPipeline)][pscustomobject]$ConfigFromPipeline,
        [Parameter(Mandatory)][string]$UserUpn, [ValidateLength(1,100)][string]$DisplayName = 'Software Passkey',
        [Parameter(ParameterSetName = 'ClientSecret')][Parameter(ParameterSetName = 'Certificate')][string]$ClientId,
        [Parameter(ParameterSetName = 'ClientSecret')][securestring]$ClientSecret,
        [Parameter(ParameterSetName = 'Certificate')][string]$ClientCertificatePath,
        [Parameter(ParameterSetName = 'Certificate')][securestring]$ClientCertificatePassword,
        [Parameter(ParameterSetName = 'ManagedIdentity')][switch]$UseManagedIdentity,
        [string]$OutputPath, [switch]$UseKeyVault, [string]$KeyVaultName, [string]$TenantId, [switch]$PassThru)
# Invoke public command
Register-EntraSoftwarePasskey @PSBoundParameters
