#Requires -Version 7.6

<#
.SYNOPSIS
    Sets up Azure resources and permissions for Key Vault-backed passkey registration.

.DESCRIPTION
    This script automates the setup of all prerequisites needed to register passkeys
    with private keys secured in Azure Key Vault. It uses only Microsoft Graph and
    Azure REST APIs for maximum simplicity.

    The script:
    1. Creates or validates service principal
    2. Adds Microsoft Graph API permission for passkey management
    3. Attempts to grant admin consent automatically (if user has permissions)
    4. Creates resource group and Key Vault with RBAC authorization
    5. Assigns Key Vault Crypto Officer role to service principal
    6. Generates client secret
    7. Outputs all parameters needed for Register-EntraSoftwarePasskey.ps1

    The script checks for existing resources and reuses them when possible.
    Before any provisioning I/O, client-secret creation requires -PassThru to return
    its unrecoverable value. Otherwise use -SkipSecret or -SkipServicePrincipal.
    Default -WhatIf remains a no-I/O preview without those switches.

.PARAMETER SubscriptionId
    Azure subscription ID. If not provided, uses current context.

.PARAMETER ResourceGroupName
    Name of resource group for Key Vault. Default: rg-passkey-keyvault

.PARAMETER KeyVaultName
    Name of Key Vault. Must be globally unique. Default: kv-passkey-[random]

.PARAMETER Location
    Azure region for resources. Default: eastus

.PARAMETER ServicePrincipalName
    Display name for service principal. Default: KeyVault-Passkey-Service

.PARAMETER KeyVaultSku
    Key Vault SKU tier. Valid values: standard, premium. Default: standard
    Premium SKU is required for HSM-backed keys and provides additional security features.

.PARAMETER EnablePurgeProtection
    Enable purge protection to prevent permanent deletion during soft-delete retention period.
    Recommended for production environments. Once enabled, cannot be disabled. Default: true

.PARAMETER PassThru
    Returns the provisioning result, including a newly generated client secret when not skipped.
    Required when creating a new client secret. The secret is never printed to diagnostic
    streams; store the returned value securely.

.PARAMETER SecretExpirationMonths
    Client secret expiration in months. Default: 12

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -SkipSecret

    Uses defaults with Standard SKU and skips creating an unneeded client secret.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -KeyVaultName "my-passkey-vault" -Location "westus2" -SkipSecret

    Creates resources with custom Key Vault name and location.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -KeyVaultSku "premium" -SkipSecret

    Creates a Premium vault, which permits EC-HSM keys. Registration currently creates EC keys.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -EnablePurgeProtection $false -SkipSecret

    Creates Key Vault without purge protection (not recommended for production).

.NOTES
    Author: Nathan McNulty
    Date: February 6, 2026

    Prerequisites:
    - Microsoft.Graph.Authentication and Az.Accounts modules installed
    - Logged in to Microsoft Graph and Azure
    - Application.ReadWrite.All permission (to create app)
    - AppRoleAssignment.ReadWrite.All permission (to grant consent, optional)
    - Contributor or Owner on Azure subscription (to create resources)

    Research provisioning uses RBAC and soft-delete configuration. It is not a
    supported security service and does not claim benchmark or production compliance.
    Premium vault SKU permits EC-HSM keys, but registration currently requests EC keys.

    WARNING: Purge protection cannot be disabled once enabled on a Key Vault.
    This is intentional to protect against insider threats and accidental deletion.

    Research-only command. WhatIf performs no authentication, network requests or output writes.
    Registration uses none attestation with AT-only flags (0x40), without UP or UV claims.
    Initialization may grant app permissions and create a client secret unless those steps are skipped.
    Client-secret creation requires -PassThru; otherwise use -SkipSecret or -SkipServicePrincipal.
    Capture the returned configuration and store the secret securely; it cannot be retrieved again.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-passkey-keyvault",

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "KeyVault-Passkey-Service",

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard", "premium")]
    [string]$KeyVaultSku = "standard",

    [Parameter(Mandatory = $false)]
    [bool]$EnablePurgeProtection = $true,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServicePrincipal,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSecret,

    [Parameter(Mandatory = $false)]
    [switch]$SkipKeyVault,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

# Invoke public command
Initialize-EntraPasskeyKeyVault @PSBoundParameters
