# Passkey login credential contract

PowerShell and Python login now share a documented credential contract at `contracts\passkey-login-credential.schema.json`.

## Purpose

This contract defines the stored credential shape consumed by:

- `powershell\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1`
- `python\libraries\passkey\src\passkey\entra_login.py`
- `python\samples\entra\invoke_entra_passkey_login.py`

It is the contract downstream repos should target when they want one stored passkey record to work across both languages.

## Canonical fields

New writers should prefer these names:

| Field | Required | Notes |
| --- | --- | --- |
| `credentialId` | Yes | Base64url credential ID is preferred; UUID input is still accepted by readers. |
| `userHandle` | Yes | Base64url-encoded FIDO2 user handle. |
| `userName` | Yes | Canonical sign-in name for the user. |
| `relyingParty` | Yes | RP ID, usually `login.microsoft.com`. |
| `url` | Recommended | Origin URL used to derive `clientDataJSON` origin. |
| `signCount` | Recommended | Signature counter. Readers default to `0` when omitted. |
| `keyVault` or `privateKey` | Yes | Choose Key Vault-backed or local-key signing material. |

## Backward-compatible aliases

The current readers still accept these aliases to avoid breaking older records:

| Canonical field | Accepted aliases |
| --- | --- |
| `userName` | `username`, `userPrincipalName` |
| `relyingParty` | `rpId` |
| `signCount` | `counter` |
| `privateKey` | `keyValue` |

## Key Vault-backed example

```json
{
  "credentialId": "AbCd1234EfGh5678IjKl",
  "userHandle": "ExAmPlE_UsErHaNdLe",
  "userName": "user@tenant.onmicrosoft.com",
  "relyingParty": "login.microsoft.com",
  "url": "https://login.microsoft.com",
  "signCount": 0,
  "keyVault": {
    "vaultName": "kv-sml-passkeys",
    "keyName": "passkey-user-20260630-120000",
    "keyId": "https://kv-sml-passkeys.vault.azure.net/keys/passkey-user-20260630-120000/version"
  }
}
```

## Local-key example

```json
{
  "credentialId": "AbCd1234EfGh5678IjKl",
  "userHandle": "ExAmPlE_UsErHaNdLe",
  "userName": "user@example.com",
  "relyingParty": "login.microsoft.com",
  "url": "https://login.microsoft.com",
  "signCount": 0,
  "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

## Current writer behavior

The current PowerShell registration flow writes a compatible record with:

- `userName`
- `credentialId`
- `userHandle`
- `relyingParty`
- `url`
- `keyVault`

It does not currently emit `signCount`; both login implementations already treat a missing counter as `0`.
