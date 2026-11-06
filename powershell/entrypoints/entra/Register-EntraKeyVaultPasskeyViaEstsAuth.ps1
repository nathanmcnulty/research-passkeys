#Requires -Version 7.6

<#
.SYNOPSIS
    Registers a FIDO2 passkey using an ESTSAUTH cookie, with the credential
    private key stored in Azure Key Vault.

.DESCRIPTION
    Replicates the browser's mysignins.microsoft.com passkey registration flow using
    an ESTSAUTH/ESTSAUTHPERSISTENT cookie for silent SSO authentication. The credential
    private key is generated in Azure Key Vault (never exported) instead of saved to a
    local file.

    Only the cookie is required — the tenant is resolved automatically via the
    'organizations' authorize endpoint and confirmed from the JWT tid claim.
    UserPrincipalName is also extracted from the JWT after token exchange.

    Flow:
    1. Key Vault Setup: Acquire KV token, create EC P-256 key in Key Vault
    2. Silent Auth: Injects ESTSAUTH cookie → authorize (no prompt) → 302 with auth code
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

.PARAMETER ESTSAuthCookie
    Value of an ESTSAUTH or ESTSAUTHPERSISTENT cookie from login.microsoftonline.com.
    Obtain from browser DevTools → Application → Cookies → login.microsoftonline.com.

.PARAMETER KeyVaultName
    The name of the Azure Key Vault where the credential key will be stored.
    The user must have Key Vault Crypto Officer or equivalent key-creation permission on this vault.

.PARAMETER TenantId
    Optional. Azure AD tenant ID (GUID). If not specified, the 'organizations' endpoint
    is used for initial auth and the tenant is resolved from the JWT tid claim.

.PARAMETER KeyVaultKeyName
    Name for the key in Key Vault. Auto-generated as passkey-<upnprefix>-<timestamp>
    if not specified.

.PARAMETER PasskeyDisplayName
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
    # Minimal — only the cookie and Key Vault name are required
    .\Register-EntraKeyVaultPasskeyViaEstsAuth.ps1 -ESTSAuthCookie "1.AVIA..." -KeyVaultName "my-keyvault"

.EXAMPLE
    # With explicit tenant ID
    .\Register-EntraKeyVaultPasskeyViaEstsAuth.ps1 -ESTSAuthCookie $cookie -KeyVaultName "my-keyvault" `
        -TenantId "<tenant-id>"

.EXAMPLE
    # With pre-obtained Key Vault token (skips Az/CLI checks)
    .\Register-EntraKeyVaultPasskeyViaEstsAuth.ps1 -ESTSAuthCookie $cookie -KeyVaultName "my-keyvault" `
        -KeyVaultAccessToken (az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)

.NOTES
    Author: Nathan McNulty
    Date: March 1, 2026

    Flow follows mysignins.microsoft.com passkey registration.
    The browser uses ESTS native endpoints (fido/create → newfido), NOT the Graph API.
    The credential private key is protected by Key Vault and never leaves it.

    Research-only command. WhatIf performs no authentication, network requests or output writes.
    Registration uses none attestation with AT-only flags (0x40), without UP or UV claims.

#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [object]$ESTSAuthCookie,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$PasskeyDisplayName = "",

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
Register-EntraKeyVaultPasskeyViaEstsAuth @PSBoundParameters
