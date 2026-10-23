<#
.SYNOPSIS
    Registers a FIDO2 passkey using a Temporary Access Pass, with the credential
    private key stored in Azure Key Vault.
.DESCRIPTION
    Explicit research command. Supports WhatIf without authentication, network or output writes.
    Generates none attestation with AT-only flags. It does not establish authenticator-bound UP/UV.
    Unattended software implementation, not a FIDO-certified authenticator or evidence of hardware assurance.
    Returns the confirmed credential record after writing its public Key Vault reference.
#>
function Register-EntraKeyVaultPasskey {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [object]$TAP,

    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$DisplayName = "",

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',

    [Parameter()]
    [string]$RedirectUri = 'https://mysignins.microsoft.com'
)
    $arguments = @{} + $PSBoundParameters
    # Forward this curated command's defaults, which differ from the reference TAP command.
    $arguments.DisplayName = $DisplayName
    $arguments.UserAgent = $UserAgent
    $arguments.RedirectUri = $RedirectUri
    Register-EntraKeyVaultPasskeyViaTap @arguments
}
