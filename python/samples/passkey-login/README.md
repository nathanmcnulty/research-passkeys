# Python passkey login sample

This sample uses `python\libraries\passkey` to authenticate with a previously registered passkey credential.

It is intended to prove:

- the credential JSON contract
- Azure Key Vault-backed signing
- cross-language parity with the PowerShell login path

## Usage

1. Install dependencies:

   ```powershell
   pip install requests cryptography azure-identity
   ```

2. Run the sample:

   ```powershell
   python .\login_keyvault_passkey.py --credential-path .\credential.json
   ```

Optional parameters:

- `--keyvault-access-token`
- `--keyvault-tenant-id`
- `--keyvault-client-id`
- `--keyvault-client-secret`
- `--auth-url`

On success, the sample prints the ESTS cookie type and cookie value that were issued.
