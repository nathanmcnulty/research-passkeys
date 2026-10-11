# Changelog

## v1.1.0 - 2026-03-21

Improves private-key workflow isolation and release readiness after the first public release.

Highlights:

1. Added dedicated repository secret names for the local private-key workflow:
	- `PASSKEY_PRIVATE_CREDENTIAL_ID`
	- `PASSKEY_PRIVATE_USER_HANDLE`
	- `PASSKEY_PRIVATE_USER_PRINCIPAL_NAME`
	- `PASSKEY_PRIVATE_KEY`
2. Supports storing Key Vault-backed and local private-key registration values in the same repository at the same time without secret-name collisions.
3. Hardened the private-key authentication verification path so the action can better finalize and inspect session cookies before returning outputs.

## v1.0.0 - 2026-03-21

Initial public release of the Passkey Login Action.

Purpose:

1. Authenticate to Entra with a passkey.
2. Prefer Azure Key Vault-backed signing for automation.
3. Return an `ESTSAUTH` cookie for downstream tools and validation flows.

Included in this release:

1. Composite GitHub Action defined in [action.yml](action.yml).
2. PowerShell authentication implementation in [PasskeyLogin.ps1](PasskeyLogin.ps1).
3. Key Vault-first workflow guidance and setup documentation in [README.md](README.md).
4. Optional onboarding helpers in [scripts/Setup-GitHubActionServicePrincipal.ps1](scripts/Setup-GitHubActionServicePrincipal.ps1).
5. Sanitized example passkey templates in [examples/passkey.private-key.example.json](examples/passkey.private-key.example.json) and [examples/passkey.keyvault.example.json](examples/passkey.keyvault.example.json).
6. Validation workflows for Key Vault-backed authentication and XDR session bootstrap.

Security posture:

1. Azure Key Vault is the recommended signing path.
2. Local private key support remains available as a fallback for controlled testing.
3. The action masks sensitive values and treats the returned cookie as sensitive session material.
## Unattended application confirmation and output hardening

- Use Azure CLI’s HTTPS native callback by default to avoid its native-scheme application-confirmation prompt. Stop remaining application-confirmation interrupts by default; explicit operator opt-in is bound to the expected authorization client. This confirmation is separate from OAuth permission consent.
- Omit shortened credential identifiers because masking their full values does not mask prefixes.
- Add offline tests for confirmation rejection before any HTTP submission.
