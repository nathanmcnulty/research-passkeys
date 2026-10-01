# Repository reconciliation

Reviewed 2026-09-28 against research `main` at `2e38eb569d8d8a84ac915c4d783ffbc8cf02fe9c` and provider `main` at `2fba00ed462061f08e4edc2ebf9dc68de9625aef`. Recheck those revisions before applying a later decision.

## What was preserved and brought current

The older `E:\research-passkeys` checkout had three two-line documentation edits and an untracked 110-line `ROADMAP.md` written against `1e797518` on 2026-09-12. All four files are preserved in [`codex/preserve-20260912-roadmap`](https://github.com/nathanmcnulty/research-passkeys/tree/codex/preserve-20260912-roadmap) at `ea38f26`. This branch is a review copy, **not** a proposed merge into current `main`. The local `main` checkout was then fast-forwarded by 26 commits to `origin/main`; no original edit was discarded.

| Preserved work | Current disposition |
| --- | --- |
| `README.md` link to the old roadmap | Do not copy as-is: the old roadmap points to a sibling local provider checkout and predates the current research/provisioning work. This document is the current entry point. |
| `browser-extensions/TODO.md` warning about disabled assertions and Queue/Easy Auth drift | Superseded by the newer 2026-09-27 warning and [extension reconciliation](browser-extensions/reconciliation.md). Function assertions still return 501, and the research browser adapter denies before network. |
| `function-app/TODO.md` warning that Bicep authentication exists but deployed behavior needs proof | Aligned with the later reported management-plane validation in two isolated labs. Direct HTTP authorization is still unverified, and the dated route inventory remains source-only evidence. |
| `ROADMAP.md` staged local, deployed Function, Entra/Okta, and broker plans | Retained for review. Its still-useful questions belong in the current [route inventory](docs/research-route-inventory-2026-09-26.md), [broker lifecycle contract](contracts/broker-proof-lifecycle-v1.md), or a focused new work item, rather than restoring a second competing roadmap wholesale. |

## Component ownership and parity

The hardened native provider and browser extension live in `keyvault-passkey-provider/src/dotnet-provider` and `keyvault-passkey-provider/src/browser-extension` in the provider repository. Research owns shared contracts, isolated Function experiments, and a pinned, immutable browser-extension source copy. The current 53-file provider extension tree matches `browser-extensions/upstream-provider.lock.json` at tree `d4a18e9e99b16597663471d6e3aae61ceb82c022`; the lock's file hashes validate. The older runnable `browser-extensions/keyvault-passkey-provider` spike is divergent and has the same extension identity. Do not load or copy it over the hardened extension. Promote a bounded experiment to the provider through a reviewed provider PR, then refresh the research lock. The [provider component security review](https://github.com/nathanmcnulty/keyvault-passkey-provider/blob/main/plans/component-security-review-2026-09-28.md) records the current native, browser, and research Function findings and clean-host gates.

The old spike has four files absent from the provider extension. Their disposition is narrower than a wholesale source sync:

| Old-spike-only file | Disposition |
| --- | --- |
| `public/opening.html` | Opening-page/User-Agent routing experiment. Keep outside the hardened release until its navigation and origin behavior receives a separate threat review. |
| `scripts/New-BrowserFunctionAppRegistration.ps1` | Experimental app-registration helper that creates an app/service principal. The optional device-authentication switch was removed, but the historical helper is still outside provider validation and must not be run as part of it. |
| `scripts/validate-function-catalog-adapter.mjs` | Historical validator expects a Function assertion result, while the current client deliberately rejects assertions before network. Do not use it as evidence of a working broker assertion. |
| `src/shared/function-catalog-client.ts` | Mixes read-only catalog mapping with assertion, browser-context, and delete methods. Its safe read-only catalog slice has already been extracted to `browser-extensions/experiments/function-catalog/`; retain the old file as comparison evidence, not a provider component. |

## Login-context deletion gate (2026-10-01)

The Python and PowerShell `DELETE /api/passkeys/{recordId}/login-context` samples deleted the versionless `pklogin-{recordId}` secret before an unconditional catalog upsert. That ordering could delete a concurrent secret version and overwrite newer catalog state. The route now returns 501 before reading the request, and both deployment templates disable the function. Any future implementation must use generation-unique secret names, make a conditional catalog update with a concrete ETag its linearization point, and clean up only the previously referenced generation after commit with durable retries.

## Decisions still open

1. **Old extension spike:** the four unique files are classified above. The 28 divergent overlapping files are inventoried below; their individual behavior still needs review before any additional promotion or retirement. The same-identity hazard prevents using it as a second installed beta.
2. **Function authorization:** join the reported management-plane lab results to exact deployment IDs/configuration and test direct HTTP denial, owner isolation, and Queue identity-plus-key behavior. The source inventory and management-plane settings do not prove HTTP enforcement.
3. **Device-code samples:** several historical samples and README entries still describe or invoke device-code authentication. They are outside the approved working path; use cached WAM/MSAL or normal browser authentication. Decide whether to archive, disable, or replace each sample in a focused change. Do not run them as part of offline validation.
4. **Public release:** the provider's [release-readiness plan](https://github.com/nathanmcnulty/keyvault-passkey-provider/blob/main/plans/public-release-readiness.md) owns visibility, signed artifact, clean-host, security, and user-experience gates. Research results do not by themselves close those gates.

Keep the preservation branch until its roadmap questions have a disposition. Do not merge it wholesale or delete the older extension solely to make the working tree look cleaner.

## Overlapping old-extension drift inventory (2026-09-28)

Compared the 28 shared files whose bytes differ between the historical `browser-extensions/keyvault-passkey-provider` tree and the hardened provider's `src/browser-extension` tree. This is an ownership and review map, not a claim that every line of either implementation has been audited. The provider remains authoritative; none of these files was copied or installed from research.

| Review slice | Differing shared files | Disposition and next proof |
| --- | --- | --- |
| Package and developer workflow | `.gitignore`, `package.json`, `package-lock.json`, `README.md`, `scripts/launch-edge-extension-session.mjs`, `scripts/validate-ctap-flow.mjs` | Keep provider dependency/build and validation workflow. Compare any research-only test scenario as a focused test addition; do not overwrite the provider's security, interception, lifecycle, and lock validators. |
| Extension identity and permissions | `public/manifest.json` | The manifest identity is the same. The old spike requests `declarativeNetRequestWithHostAccess` and optional HTTP/HTTPS access for every host; the provider omits that permission and limits optional HTTP to local loopback. Any broader routing proposal needs a separate least-privilege review and explicit user benefit before promotion. |
| Visible setup, unlock, and popup | `public/popup.css`, `public/popup.html`, `public/setup.html`, `public/uv-dialog.html`, `src/popup.ts`, `src/setup.ts`, `src/uv-dialog.ts` | Treat as UX experiments only. Compare specific flows against the provider's current idle/restart lock and recovery evidence; preserve the provider's required-UV refusal until native proof exists. |
| Browser ceremony interception | `src/background.ts`, `src/content.ts`, `src/page.ts` | Security-critical. Review origin/RP binding, cancellation, fallback, and create/get separately with current provider tests and live RP evidence. No wholesale promotion or second installed beta. |
| Authentication and Key Vault calls | `src/shared/browser-auth.ts`, `src/shared/key-vault-client.ts`, `src/shared/key-vault-metadata-transport.ts` | Review token acquisition, explicit vault host permission, authorization failures, and retry behavior as independent changes. Do not reintroduce device-code auth or general-purpose remote signing. |
| Credential storage and metadata | `src/shared/metadata-cache-store.ts`, `src/shared/metadata-store.ts`, `src/shared/models.ts`, `src/shared/storage.ts` | Review record schema and migration, Key Vault metadata recovery, and deletion semantics against the provider's current hardened lifecycle. Require compatibility and fault tests for any promotion. |
| UV, protocol, and WebAuthn bytes | `src/shared/pin-uv.ts`, `src/shared/protocol.ts`, `src/shared/setup-state.ts`, `src/shared/webauthn-data.ts` | Treat differences as security-sensitive. Compare UV flags, local PIN limits, setup state, and assertion/attestation bytes with current provider validators and RP acceptance. Browser PIN verification does not become trusted native Hello proof. |

The four old-only files above remain separately classified. This inventory closes the question of **where** shared differences live; it does not close the question of whether any individual research behavior is ready to promote. Open one bounded provider change per demonstrated improvement, validate it there, and then refresh `upstream-provider.lock.json` so research tracks the exact adopted tree.

## Public-history hygiene checkpoint (2026-09-28)

The research repository is already public. A redacted Gitleaks 8.30.1 scan of locally fetched history (`gitleaks git --log-opts='--all' --redact=100`) reported 14 candidates across 72 scanned commits. The three `private-key` hits are an example JSON line that literally contains `-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----`; it is not usable private-key material. The other hits are public extension manifest keys, a hash of that manifest key, an AAGUID, a built-in public client ID, and sample `PASSKEY_TENANT_ID` values. No authentication secret was confirmed from these scanner candidates. The redacted report remained outside the repository.

The **historical** PowerShell and Python Function sample settings contained the same concrete tenant GUID in two commits, although the current tracked samples now use `replace-with-your-tenant-id`. A tenant GUID alone is not an access credential, but it is an organization identifier already present in public history. Review whether that disclosure is acceptable before using this repository as a public-release template. Do not repeat the identifier in new documentation. Any history rewrite would require an explicit coordinated decision and would not undo copies already fetched by others. This scan is bounded by Gitleaks rules and the locally fetched refs; it is not a complete privacy or secret clearance.
