#Requires -Version 7.6

<#
.SYNOPSIS
    Registers a FIDO2 passkey using a Temporary Access Pass, with the credential
    private key stored in Azure Key Vault.

.DESCRIPTION
    Replicates the browser's mysignins.microsoft.com passkey registration flow using
    a Temporary Access Pass (TAP) for authentication. The credential private key is
    generated in Azure Key Vault (never exported) instead of saved to a local file.

    Flow:
    1. Key Vault Setup: Acquire KV token, create EC P-256 key in Key Vault
    2. TAP Login: Full login flow using AccessPass field (ps=56)
    3. Token Exchange: Auth code + PKCE → access_token + refresh_token
    4. Session Setup: session/authorize → NGC MFA claims refresh → SessionCtxV2
    5. Passkey Init: authenticationmethods/new {Type:18} → canary + serverChallenge
    6. Attestation: Builds WebAuthn attestation using the Key Vault public key and none attestation
    7. Registration: POSTs to fido/create then newfido with canary + attestation

    The credential JSON output stores a versioned Key Vault reference. Software-backed
    login remains subject to the repository user-presence and verification security gate.

    Key Vault token acquisition order:
    1. -KeyVaultAccessToken parameter (if provided)
    2. Get-AzAccessToken (Az.Accounts module, if connected)
    3. az account get-access-token (Azure CLI, if logged in)
    4. Error with instructions if none available

.PARAMETER TAP
    Temporary Access Pass value.

.PARAMETER UserPrincipalName
    The user's UPN (e.g., user@contoso.com).

.PARAMETER TenantId
    Optional enrollment tenant GUID. Defaults to validated UPN-suffix OIDC discovery.
    Supply the intended resource tenant for guest/cross-tenant enrollment. This does not select a Key Vault application tenant.
    The Azure AD tenant ID (GUID).

.PARAMETER KeyVaultName
    The name of the Azure Key Vault where the credential key will be stored.
    The user must have Key Vault Crypto Officer or equivalent key-creation permission on this vault.

.PARAMETER KeyVaultKeyName
    Name for the key in Key Vault. Auto-generated as passkey-<upnprefix>-<timestamp>
    if not specified.

.PARAMETER DisplayName
    Nonblank name, at most 30 characters; for example TokenForge 261011.
    Display name for the passkey (default: "Software Passkey").

.PARAMETER OutputPath
    Path to save the credential JSON file. Defaults to <username>_passkey_<timestamp>.json.
    An existing file at this path is overwritten after confirmed enrollment. Use a unique path.
    A save failure does not roll back the enrolled passkey or its Key Vault key. The error's
    TargetObject contains public credential metadata that can be saved for recovery.

.PARAMETER KeyVaultAccessToken
    Pre-obtained access token for https://vault.azure.net. Bypasses Az module and
    Azure CLI checks. Obtain via:
      az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv

.EXAMPLE
    .\Register-EntraKeyVaultPasskeyViaTap.ps1 -TAP "abc123" -UserPrincipalName "user@contoso.com" `
        -TenantId "847b5907-..." -KeyVaultName "my-keyvault"

.EXAMPLE
    .\Register-EntraKeyVaultPasskeyViaTap.ps1 -TAP $tap -UserPrincipalName "user@contoso.com" `
        -TenantId $tid -KeyVaultName "my-keyvault" -KeyVaultKeyName "my-passkey-key" `
        -DisplayName "YubiKey 5"

.NOTES
    Author: Nathan McNulty
    Date: March 1, 2026

    Flow discovered via HAR analysis of mysignins.microsoft.com passkey registration.
    The browser uses ESTS native endpoints (fido/create → newfido), NOT the Graph API.
    The credential private key is protected by Key Vault and never leaves it.

    Research-only command. WhatIf performs no authentication, network requests or output writes.
    Registration uses none attestation with AT-only flags (0x40), without UP or UV claims.

#>
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
    [string]$DisplayName = "Software Passkey",

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',

    [Parameter()]
    [string]$RedirectUri = 'https://mysignins.microsoft.com'
)

# Invoke public command
Register-EntraKeyVaultPasskeyViaTap @PSBoundParameters
