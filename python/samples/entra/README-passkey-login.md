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
   python .\invoke_entra_passkey_login.py --credential-path .\credential.json
   ```

Optional parameters:

- `--keyvault-access-token`
- `--keyvault-tenant-id`
- `--keyvault-client-id`
- `--keyvault-client-secret`
- `--auth-url`

On success, the sample prints the ESTS cookie type and cookie value that were issued.

## Pass the cookie to roadtx

Use the adapter when the next step is a ROADtools interactive authentication flow:

```powershell
python .\invoke_entra_passkey_roadtx.py `
  --credential-path .\credential.json `
  --roadtx-driver-path C:\path\to\geckodriver.exe
```

The adapter keeps the cookie in memory and invokes `roadtx interactiveauth --estscookie`.
It does not print or save the cookie. `roadtx` still receives the value as a process
argument because that is the interface exposed by the current ROADtools version.

Useful options include:

- `--roadtx-command` to provide a full path to the `roadtx` executable
- `--roadtx-tokenfile` to choose where roadtx writes its token data
- `--roadtx-headless` to run the roadtx browser headlessly
- `--roadtx-resource` instead of the default Graph v2 scope

The cookie is a bearer credential. Avoid recording the command line or sharing process
listings while this adapter is running.

For the complete TAP → passkey → ROADtools → ROADrecon workflow, see
[`roadtools.md`](roadtools.md).
