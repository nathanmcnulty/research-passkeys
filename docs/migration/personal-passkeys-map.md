# Canonical source and preserved public paths

Baseline inputs: research `ab7672dc891d4fd7c314c59a7d3f56120d61e4ad` (draft #33), personal `956075f678e25fcbbf5e72b5b42141da9ed33554` (draft #16), action `2688294bb0f0fcb230df071eb226f2549ec82280` (draft #3). No merge or live operational validation is implied by this source reorganization.

## Ownership decisions

- GitHub adapters, examples, documentation, and tests move from the unpublished personal draft addition to `github/adapters`. They are not copied back to personal.
- The complete 18-file action package is maintained at `github/action-passkey-login`. Existing workflows are nested and inert in research. README ownership guidance is updated; runtime implementation and workflow bytes remain unchanged from the action baseline.
- Both personal logins are generated from that one action implementation. Reviewed adaptation is limited to parameter positions/credential-ID naming and opted-in legacy session alias/output metadata. Generated outputs initially match the personal draft bytes exactly.
- Initializer and software registration are generated from `powershell/scripts/entra/reference/Initialize-EntraPasskeyKeyVault.ps1` and `Register-EntraSoftwarePasskey.ps1`. Only script-name references are adapted. The latter brings current SecureString fixes to personal; neither needs relative shared modules.
- Root and Key Vault TAP/ESTS registrations are **imported historical compatibility sources**, not relabeled copies of current research registration. Their software attestation semantics differ materially, so they are preserved separately. TAP cookie and metadata helpers likewise retain their historical implementation.
- Notifications use the existing research source. The updated template supports synced passkey/WHfB events and deduplication; its parameter contract and the PowerShell helper are unchanged. No deployed resource is changed.
- Action boundary/consent tests have one canonical source and export to both repositories. Personal-specific compatibility tests remain beside the generated personal entry points.
- The previously published DOCX remains in personal, unchanged and explicitly outside script synchronization. The manifest records its original commit and Git blob SHA.

The guarded research reference software-assertion denial and none-attestation boundaries remain untouched. Historical compatibility and GitHub experiments are not evidence of trusted hardware presence/verification and must never overwrite those guarded surfaces.

## Exact managed file map

All files below are byte-exact exports. Generated sources are checked against the renderer before export or hash refresh; `render_compatibility.py --check` also provides a standalone check. Edit the listed canonical source (or its generator input), never a downstream copy. Importing historical scripts makes future ownership explicit; it does not claim those scripts have been upgraded or security-certified.

| Canonical research source | Downstream repository | Existing/public path |
| --- | --- | --- |
| `github/action-passkey-login/.github/workflows/ci.yml` | `action-passkey-login` | `.github/workflows/ci.yml` |
| `github/action-passkey-login/.github/workflows/test-key-vault.yml` | `action-passkey-login` | `.github/workflows/test-key-vault.yml` |
| `github/action-passkey-login/.github/workflows/test-private-key.yml` | `action-passkey-login` | `.github/workflows/test-private-key.yml` |
| `github/action-passkey-login/.github/workflows/test-xdr-key-vault.yml` | `action-passkey-login` | `.github/workflows/test-xdr-key-vault.yml` |
| `github/action-passkey-login/.gitignore` | `action-passkey-login` | `.gitignore` |
| `github/action-passkey-login/CHANGELOG.md` | `action-passkey-login` | `CHANGELOG.md` |
| `github/action-passkey-login/HARDENING.md` | `action-passkey-login` | `HARDENING.md` |
| `github/action-passkey-login/LICENSE` | `action-passkey-login` | `LICENSE` |
| `github/action-passkey-login/PasskeyLogin.ps1` | `action-passkey-login` | `PasskeyLogin.ps1` |
| `github/action-passkey-login/README.md` | `action-passkey-login` | `README.md` |
| `github/action-passkey-login/SECURITY.md` | `action-passkey-login` | `SECURITY.md` |
| `github/action-passkey-login/action.yml` | `action-passkey-login` | `action.yml` |
| `github/action-passkey-login/examples/passkey.keyvault.example.json` | `action-passkey-login` | `examples/passkey.keyvault.example.json` |
| `github/action-passkey-login/examples/passkey.private-key.example.json` | `action-passkey-login` | `examples/passkey.private-key.example.json` |
| `github/action-passkey-login/scripts/Setup-GitHubActionServicePrincipal.ps1` | `action-passkey-login` | `scripts/Setup-GitHubActionServicePrincipal.ps1` |
| `github/action-passkey-login/scripts/Test-XdrConnectionByEstsCookie.ps1` | `action-passkey-login` | `scripts/Test-XdrConnectionByEstsCookie.ps1` |
| `github/action-passkey-login/tests/KeyVaultBoundary.Tests.ps1` | `action-passkey-login` | `tests/KeyVaultBoundary.Tests.ps1` |
| `github/action-passkey-login/tests/SilentConsent.Tests.ps1` | `action-passkey-login` | `tests/SilentConsent.Tests.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/Get-ESTSAuthCookieViaTAP.ps1` | `nathanmcnulty` | `Entra/passkeys/Get-ESTSAuthCookieViaTAP.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/LOGIN-MIGRATION.md` | `nathanmcnulty` | `Entra/passkeys/LOGIN-MIGRATION.md` |
| `compatibility/nathanmcnulty/Entra/passkeys/PasskeyLogin.ps1` | `nathanmcnulty` | `Entra/passkeys/PasskeyLogin.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/README.md` | `nathanmcnulty` | `Entra/passkeys/README.md` |
| `compatibility/nathanmcnulty/Entra/passkeys/Register-PasskeyViaESTSAuth.ps1` | `nathanmcnulty` | `Entra/passkeys/Register-PasskeyViaESTSAuth.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/Register-PasskeyViaTAP.ps1` | `nathanmcnulty` | `Entra/passkeys/Register-PasskeyViaTAP.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/get-passkey-metadata.ps1` | `nathanmcnulty` | `Entra/passkeys/get-passkey-metadata.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/Initialize-PasskeyKeyVault.ps1` | `nathanmcnulty` | `Entra/passkeys/keyvault/Initialize-PasskeyKeyVault.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/New-KeyVaultPasskey.ps1` | `nathanmcnulty` | `Entra/passkeys/keyvault/New-KeyVaultPasskey.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/PasskeyLogin.ps1` | `nathanmcnulty` | `Entra/passkeys/keyvault/PasskeyLogin.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/README.md` | `nathanmcnulty` | `Entra/passkeys/keyvault/README.md` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/Register-KeyVaultPasskeyViaESTSAuth.ps1` | `nathanmcnulty` | `Entra/passkeys/keyvault/Register-KeyVaultPasskeyViaESTSAuth.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/keyvault/Register-KeyVaultPasskeyViaTAP.ps1` | `nathanmcnulty` | `Entra/passkeys/keyvault/Register-KeyVaultPasskeyViaTAP.ps1` |
| `samples/notifications/README.md` | `nathanmcnulty` | `Entra/passkeys/notifications/README.md` |
| `samples/notifications/mfa-registration-notification.json` | `nathanmcnulty` | `Entra/passkeys/notifications/mfa-registration-notification.json` |
| `samples/notifications/mfa-registration-notification.ps1` | `nathanmcnulty` | `Entra/passkeys/notifications/mfa-registration-notification.ps1` |
| `github/action-passkey-login/tests/KeyVaultBoundary.Tests.ps1` | `nathanmcnulty` | `Entra/passkeys/tests/KeyVaultBoundary.Tests.ps1` |
| `compatibility/nathanmcnulty/Entra/passkeys/tests/LoginCompatibility.Tests.ps1` | `nathanmcnulty` | `Entra/passkeys/tests/LoginCompatibility.Tests.ps1` |
| `github/action-passkey-login/tests/SilentConsent.Tests.ps1` | `nathanmcnulty` | `Entra/passkeys/tests/SilentConsent.Tests.ps1` |

## Only removed paths

The manifest's `removed` entries are the nine unpublished `Entra/passkeys/github/` draft files now hosted at `github/adapters/` in research. Removal requires the recorded original SHA-256, so a changed downstream file cannot be silently deleted. No original root/Key Vault/notification script or historical guide is removed.

## Verification and operation

Follow [downstream consumption](downstream-consumption.md#maintained-github-and-personal-repository-mirrors) for the renderer, hash refresh, offline test, export, and drift-check commands. No background sync, GitHub permission change, credential access, TAP use, registration, upload, or live authentication is part of this flow. Publication remains review-first and cross-repository updates are separate commits.
