# Python passkey registration sample

This local CLI wraps the canonical `python\libraries\passkey` registration code so Python has the same local registration surface as the Function sample.

Supported modes:

- `tap`: register with a Temporary Access Pass
- `estsauth`: register with an existing ESTSAUTH cookie

## Usage

1. Install dependencies:

   ```powershell
   pip install requests cryptography cbor2 azure-identity
   ```

2. Set the same environment variables used by the Function sample, or pass the equivalent CLI options:

   - `PASSKEY_TENANT_ID`
   - `PASSKEY_KEYVAULT_NAME`
   - `PASSKEY_MANAGED_IDENTITY_CLIENT_ID`
   - `PASSKEY_KEYVAULT_ACCESS_TOKEN`

3. Run the sample:

   ```powershell
   python .\register_entra_keyvault_passkey.py --user-principal-name user@tenant.onmicrosoft.com tap --tap replace-with-tap
   ```

ESTSAUTH mode:

```powershell
python .\register_entra_keyvault_passkey.py --user-principal-name user@tenant.onmicrosoft.com estsauth --ests-auth replace-with-cookie
```

Optional parameters:

- `--display-name`
- `--keyvault-key-name`
- `--output-path`
- `--tenant-id`
- `--keyvault-name`
