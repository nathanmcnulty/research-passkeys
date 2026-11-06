# Changelog

## Unreleased controller follow-up

- Add a fail-closed identity-only server-backed session-reuse probe for an explicitly configured public-client compatibility scenario. Synthetic/offline checks are not live acceptance.
- Require fresh code/PKCE, state/nonce and direct TLS token-response checks, followed by matching UserInfo subject. Do not silently select a client or request resource/refresh-token scopes for the test.
- Keep same-runner limitations explicit; allow the final result only when admission, cookie contract and server probe all succeed. Setup, bootstrap, hosted CI and live dispatch remain separately authorized.

## Source package 0.3.2 (unreleased)

- Prepare a protected, exact-revision manual lab cookie-output-contract controller and offline boundary tests. Independent authenticated readback remains unimplemented; the end-to-end workflow gate deliberately cannot pass.
- Retire the old manual private-key example at this revision and use separate environment-only lab secret names. Old workflow revisions are not revoked.
- The canonical registration/export helper gains an explicit protected-lab destination without changing its legacy default. Account enrollment, secret storage, controller publication and live dispatch remain separate authorized actions.
- Regenerate shared artifacts for source package 0.3.2; no release tags change.

## Source package 0.3.1

- Refuse ambiguous application display-name matches before selecting or modifying Entra trust.
- Report XDR portal bootstrap separately from authentication; require one successful form-exchange response, and never infer authenticated access from arbitrary cookies.
- Add credential-free regression coverage and document a proposed, unimplemented protected live-validation path.


## Upcoming: shared source package 0.2.0

The login script is generated from the reviewed `research-passkeys` source units,
which also build a module and standalone registration tools. Source package version
0.2.0 is independent of the historical Action release versions below; no release tags
are changed. Named Action inputs/output masking remain compatible. PowerShell 7.6
is required. Offline CI uses the hosted runner's installed PowerShell, validates major
7/minor 6 without a patch pin or runtime download, and installs Pester 6.2.0.

Legacy local/software and Key Vault assertion support remains experimental. Software
login emits one shared limitations warning per invocation, without session suppression.
Genuine authentication failure diagnostics retain warning severity.
The canonical registration commands use that warning instead of attestation-acceptance switches;
packed/none formats and existing wire behavior remain unchanged. Software
UP/UV claims are not trusted authenticator evidence. Pending consent/policy states
cannot be mistaken for completed authentication merely because an ESTS cookie exists.

Native software enrollment now durably saves its private recovery credential before
credential submission and retains it for reconciliation after uncertain or partial failure.
The separate `Register-GitHubPasskeyViaTAP` adapter has one breaking API change: callers
must provide `RecoveryOutputPath`. This parameter does not change the GitHub Action's
inputs or the login-only `PasskeyLogin.ps1` interface.

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
