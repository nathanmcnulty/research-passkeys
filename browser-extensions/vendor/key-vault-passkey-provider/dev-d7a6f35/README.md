# Browser Extension Spike

This project is the standalone MV3 spike for the Key Vault Passkey Provider browser track.

Current scope:

- inject a page-world WebAuthn shim at document start on explicitly allowed sites
- relay `navigator.credentials.create()` and `navigator.credentials.get()` calls through content and background scripts
- store extension enablement and Key Vault config locally
- maintain an encrypted local metadata cache plus a Key Vault secret-backed manifest/index for remote recovery
- support initial Key Vault-backed `create()` and `get()` flows for `ES256` passkeys when interactive Entra sign-in is available
- fall back to native browser WebAuthn when extension intercept is disabled

Target architecture:

- canonical encrypted metadata envelopes shared across Windows, browser, and future mobile clients
- local IndexedDB cache for performance only
- Key Vault metadata-key wrapping, matching the Windows client design
- first sync transport uses deterministically named Key Vault secrets for encrypted envelopes plus a manifest secret for record discovery instead of `secrets/list`
- browser-local metadata wrapping remains a bootstrap-only implementation and should not be the long-term cross-platform mode

Current browser Key Vault path:

- popup can perform interactive Entra sign-in with `chrome.identity.launchWebAuthFlow`
- Key Vault-backed metadata mode uses the same `KeyVaultWrap` content-key protection mode as the Windows path
- the popup now exposes a first-run setup wizard that walks through config save, interactive sign-in, and mandatory PIN setup in that order; the extension stays disabled until that PIN step succeeds
- registration creates a unique `EC` or `EC-HSM` P-256 signing key per passkey and persists encrypted metadata through the manifest-backed secret transport
- assertions load the matching encrypted record set, rebuild authenticator data, and sign with the stored Key Vault key identifier
- if cloud auth is not ready, popup summaries fall back to the encrypted local cache instead of attempting remote enumeration
- the unpacked extension manifest now carries a stable public key so the Chromium redirect URI stays repeatable across fresh dev profiles

Current lock model:

- once setup is complete, the extension behaves like a lockable authenticator instead of a long-lived signed-in session
- idle lock defaults to `15` minutes and can be configured between `5` and `60` minutes from setup/options
- browser restart and idle expiry return the extension to `Locked`
- unlock is PIN-first; in Key Vault mode the extension then attempts silent SSO automatically before surfacing any interactive sign-in recovery
- all PIN verification paths share persistent attempt throttling: five failures trigger exponential backoff starting at 30 seconds and capped at 15 minutes
- `Sign out` clears only the extension's cached auth state and returns the extension to a locked state; it does not perform a browser-wide Microsoft sign-out
- popup status now distinguishes setup-required, locked, unlocked, and session-expired states
- popup now shows current-site origin, host-access status, matching stored passkeys, and explicit `Allow on this site` / `Remove access` controls
- host access is now requested per site through optional host permissions, with dynamic content-script registration for granted sites
- granted origins are intercepted in top documents and child frames; embedding a granted child origin does not grant the unapproved top-level site access
- the toolbar action opens the status and management UI as a persistent side panel

Current limitations:

- each supported ceremony now requires a fresh extension-owned approval before setting UP; extension unlock alone is not treated as per-ceremony presence
- only one approval window may be active; page aborts and timeouts cancel it, its expiry is capped by the WebAuthn timeout, and service-worker teardown cannot preserve an approval for replay
- `userVerification = required` fails closed because the software-only extension does not yet have a Windows Hello/native verifier within its authenticator boundary; the extension PIN is only a lock factor
- discoverable assertions with more than one matching account use the extension-owned authorization window; account options are not exposed to page context, but the experience is not browser-native credential mediation
- all registrations return `none` attestation, a zero AAGUID, and no claimed attachment or transport
- direct delegated Key Vault access remains a development-only path until the constrained broker replaces it
- credential records now move through `pending`, `active`, `disabled`, `deleting`, and durable `deleted` states; only `active` records can satisfy WebAuthn requests, while incomplete, disabled, or failed-deletion records remain visibly manageable
- Key Vault metadata is authoritative: a successful remote snapshot atomically replaces the disposable local cache instead of merging stale local credentials back into use
- in one live extension worker, metadata mutations are serialized and assertion counters are refreshed immediately before signing
- the returned browser credential objects are reconstructed in page script and should still be treated as a compatibility spike until they are exercised against more relying parties
- Key Vault secret manifests and sign counters are not atomic across browsers or worker restarts; production requires broker-side conditional updates, idempotency, tombstone retention, and orphan reconciliation
- if a tab was already open when host access is granted or removed, that page may still need a reload to guarantee the expected document-start interception state

## Commands

```powershell
npm install
npm run build
npm run typecheck
npm run validate:security
npm run validate:lock -- --dry-run
npm run validate:interception
npm run edge:ctap
$env:KVPP_ALLOW_LIVE_KEY_VAULT_TESTS = "1"
npm run validate:ctap
```

`npm run validate:interception` launches a disposable Edge profile without invoking a Key Vault operation. It stages a temporary extension with access restricted to `https://ctap.dev/*`, verifies top-document and cross-origin child-frame interception, checks browser-derived origin/top-origin display, side-panel state and layout, PIN throttling, cancellation, concurrent-request rejection, authorization expiry, and negative WebAuthn failures without cloud mutations.

`npm run validate:lock` runs the disposable browser-lock validator. It reports redacted JSON for the 15-minute default, 5/60-minute clamps, idle expiry, protected-action rejection, cached-token-key clearing, and service-worker reload persistence. The default run simulates elapsed idle time while exercising the production state transition; pass `-- --wall-clock-idle` to wait through the real five-minute minimum. It also attempts a process-restart check, but reports that case blocked when command-line loading reinstalls the unpacked extension and resets the disposable setup before `onStartup` can be observed. Use `--dry-run` for a noninteractive case listing. It does not navigate to a relying party or call WebAuthn, and it does not create credentials or Key Vault keys. Live silent SSO and interactive recovery are separate phases; interactive recovery is reported blocked unless a normal browser session produces the required interaction condition.

For a genuine browser-start check, install `dist` once into a disposable Edge profile and set `KVPP_LOCK_INSTALLED_PROFILE` to that profile directory before running `validate:lock`. The validator then launches without command-line extension-loading flags, preserves the disposable profile, and exercises the installed extension's normal startup path.

Add `-- --live-sso` only for an explicitly authorized live identity session. The validator reads the existing ignored development-environment artifact without printing its configuration or PIN, requires the once-installed disposable profile, and pauses for normal interactive Entra sign-in. It then checks PIN-first silent SSO after a service-worker reload and clears cookies only inside that disposable profile to exercise explicit interactive recovery. It does not use device-code authentication or invoke WebAuthn.

`npm run edge:ctap` stages the same target-scoped test manifest, launches Microsoft Edge through a Playwright persistent context, and refuses to continue if the page-world WebAuthn shim is not active. This prevents an inactive extension from silently handing the test request to Windows Hello.

`npm run validate:security` checks malicious vault destinations, key identifiers, authority hosts, and OAuth redirect/state binding without cloud access.

`npm run validate:ctap` runs the interactive `ctap.dev` matrix and creates live Key Vault keys and credential metadata. It refuses to start unless `KVPP_ALLOW_LIVE_KEY_VAULT_TESTS=1` explicitly acknowledges those mutations. Supported ceremonies approve an extension-owned user-presence window; a required-UV ceremony is expected to fail closed. During development, the validator still hydrates config and an extension-lock PIN from `artifacts/browser-extension-dev-environment.json` so setup can complete.

To load the extension in Edge or Chrome:

1. Open the browser extensions page.
2. Enable developer mode.
3. Load the unpacked extension from `src/browser-extension/dist` after running the build.
4. Open the extension side panel on the target site, choose **Allow On This Site**, and reload any page that was already open before access was granted.
5. Confirm the side panel reports that host access is granted before starting a WebAuthn ceremony.
6. If you want interactive Key Vault access, add the extension redirect URI reported by `chrome.identity.getRedirectURL("aad")` to your Entra app registration. The resulting URI shape is `https://<extension-id>.chromiumapp.org/aad`.
