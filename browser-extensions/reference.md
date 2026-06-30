# Browser-extension reference sources

Relevant browser-extension material currently lives in:

- `key-vault-passkey-provider\src\browser-extension`
- `key-vault-passkey-provider\docs\browser-webauthn-review.md`
- `key-vault-passkey-provider\docs\architecture.md`

The most reusable parts to pull toward `contracts\` and `shared\` are:

- credential and envelope models
- metadata-store and cache behavior
- Key Vault metadata transport conventions
- browser auth/session assumptions that need cross-track documentation

The most browser-specific parts that should stay in this track are:

- page/content/background worker wiring
- popup/setup UI
- browser-specific WebAuthn interception and UX logic
