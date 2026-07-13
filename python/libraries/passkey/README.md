# passkey Python library

This package is the canonical Python implementation for passkey research in this repository.

It currently includes:

- TAP registration against `mysignins.microsoft.com` with Azure Key Vault-backed keys
- ESTSAUTH registration against `mysignins.microsoft.com` with Azure Key Vault-backed keys
- passkey login for Key Vault-backed and local-key credentials
- Okta MyAccount registration-start and IDX registration/login helpers used by the Function sample

Current consumers:

- `function-app\python\keyvault-passkey-http`
- `python\samples\entra\invoke_entra_passkey_login.py`

The Function App sample can sync the current library into its deployable `src\passkey` folder by running:

```powershell
.\scripts\Sync-PasskeyLibrary.ps1
```
