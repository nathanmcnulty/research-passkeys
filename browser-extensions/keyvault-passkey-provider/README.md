# Key Vault Passkey Provider browser extension

This project is an MV3 development authenticator for the Function App samples in `research-passkeys`.

Current scope:

- inject a page-world WebAuthn shim at document start on explicitly allowed sites
- relay `navigator.credentials.create()` and `navigator.credentials.get()` calls through content and background scripts
- store only the Function URL, Entra application identifiers, and browser-local PIN state
- discover active passkeys from the Function catalog
- send constrained assertion requests to the Function, which signs through its managed identity and advances the Table counter
- fall back to native browser WebAuthn when extension intercept is disabled

The browser does not receive a Key Vault token or a Function key. `navigator.credentials.create()` falls back to the native browser authenticator; passkeys intended for this adapter are created through the Function sample's registration routes.

## Setup

Publishing the extension is not required. [`public/manifest.json`](public/manifest.json) contains a fixed public `key`, so unpacked loads retain extension ID `mnghojmmlcilooejpooghcfndoclbajp` and redirect URI `https://mnghojmmlcilooejpooghcfndoclbajp.chromiumapp.org/aad`.

1. Create the single-tenant public client/API registration:

   ```powershell
   ./scripts/New-BrowserFunctionAppRegistration.ps1
   ```

   The script requires only `Microsoft.Graph.Authentication`; all directory operations use `Invoke-MgGraphRequest`. It derives the redirect from the manifest, creates `api://<client-id>/access_as_user`, and writes the resulting IDs under `.local/`. No client secret is created.

2. Pass the resulting client ID as the Bicep `browserExtensionClientId` parameter when deploying either Function sample. Easy Auth protects the Function API and validates that audience/client. The two queue-ingress routes are excluded from Easy Auth and retain `authLevel: function`:

   - `/api/entra/passkeys/register/estsauth/queue`
   - `/api/okta/passkeys/register/idx/queue`

3. Build and load `dist/` as an unpacked extension, then enter only:

   - tenant ID
   - application client ID
   - Function App base URL
   - idle lock timeout

4. Sign in and set the extension PIN. The first API scope request can display a normal user-consent prompt unless tenant policy requires administrator consent. Sign-in uses the browser profile's Microsoft session, so the selected account can remain signed in to Microsoft services in that profile.

## POC security boundary

The catalog, browser-context, delete, and assertion routes use `authLevel: anonymous` intentionally: App Service Easy Auth authenticates them before the Functions host. The browser-context route returns only provider, RP ID, username, and the captured User-Agent; it never exports a stored password. The delete operation removes the catalog row, login-context secret, and signing key (Key Vault soft-delete may retain the deleted key for recovery). The assertion operation accepts an RP ID and client-data hash, verifies the catalog record and configured vault, constructs authenticator data server-side, invokes only that record's Key Vault key, and advances `signCount`. It is not a general signing endpoint.

This is still a POC. Easy Auth authenticates the caller but the sample does not yet enforce per-user ownership of catalog records, and the PowerShell counter update does not yet use Table ETag compare-and-swap. Production broker work remains in [`../TODO.md`](../TODO.md).

Legacy direct-Key-Vault code remains internally for comparison but is no longer exposed by the setup wizard.

Current browser path:

- both legacy direct-Key-Vault and Function modes use `chrome.identity.launchWebAuthFlow`; Function mode requests the Function API audience rather than Key Vault
- the toolbar action opens a persistent side panel; the separate setup wizard walks through config save, interactive sign-in, and mandatory PIN setup in that order
- registration falls back to native WebAuthn
- assertions select a catalog record and call the constrained Function endpoint
- each Function-backed Entra passkey has an **Open** action that retrieves its captured User-Agent, opens Outlook with `login_hint` and `prompt=none`, and applies a tab-scoped header rule only to Outlook and Entra login hosts; Outlook owns the resulting native sign-in flow
- **Remove** deletes the Function catalog row, stored login context, and Key Vault signing key (subject to Key Vault soft-delete retention)
- if cloud auth is not ready, side-panel summaries fall back to the encrypted local cache instead of attempting remote enumeration
- the unpacked extension manifest now carries a stable public key so the Chromium redirect URI stays repeatable across fresh dev profiles

Current lock model:

- once setup is complete, the extension behaves like a lockable authenticator instead of a long-lived signed-in session
- idle lock defaults to `15` minutes with options for `5`, `15`, `30`, `60`, `120`, `240`, or `480` minutes
- browser restart and idle expiry return the extension to `Locked`
- unlock is PIN-first and reuses the cached Function API token while it remains valid; an expired token requires signing in again
- `Sign out` clears only the extension's cached auth state and returns the extension to a locked state; it does not perform a browser-wide Microsoft sign-out
- side-panel status distinguishes setup-required, locked, unlocked, and session-expired states
- the side panel shows current-site origin, host-access status, matching stored passkeys, and explicit `Allow on this site` / `Remove access` controls
- host access is now requested per site through optional host permissions, with dynamic content-script registration for granted sites

Current limitations:

- `userVerification = required` is satisfied by a browser-local extension PIN ceremony; without a configured PIN the extension fails closed instead of asserting UV it did not earn
- discoverable assertions with more than one matching account use a custom in-page chooser rather than browser-native credential mediation
- synthetic packed attestation is now restricted to the explicit Entra compatibility path; general relying parties get `none` attestation plus opaque defaults instead of invented provenance signals
- the returned browser credential objects are reconstructed in page script and should still be treated as a compatibility spike until they are exercised against more relying parties
- if a tab was already open when host access is granted or removed, that page may still need a reload to guarantee the expected document-start interception state
- the compatibility User-Agent rule changes the HTTP header only; JavaScript-visible User-Agent and Client Hints remain the browser's real values
- Easy Auth does not yet enforce per-user catalog ownership, so the POC delete route must not be treated as a production authorization design

## Commands

```powershell
npm install
npm run build
npm run typecheck
npm run edge:ctap
npm run validate:ctap
npm run validate:function-catalog
```

`npm run validate:function-catalog` bundles the TypeScript adapter in memory and verifies bearer headers, catalog mapping, assertion requests, and HTTPS enforcement.

`npm run edge:ctap` launches Microsoft Edge through a Playwright persistent context, loads the unpacked extension from `dist`, opens `https://ctap.dev`, and prints whether the page-world WebAuthn shim is active.

`npm run validate:ctap` runs the automated `ctap.dev` matrix, including required-UV ceremonies driven by the extension PIN verifier.

Set `ENTRA_TEST_ACCOUNT_EMAIL` only when the automated sign-in flow must select a specific account from the Microsoft account picker; the value is read from the environment and is not stored in the repository.

To load the extension in Edge or Chrome:

1. Open the browser extensions page.
2. Enable developer mode.
3. Load the unpacked extension from `browser-extensions/keyvault-passkey-provider/dist` after running the build.
4. Run the registration script before setup; it adds the stable unpacked-extension redirect URI to the Entra application.
