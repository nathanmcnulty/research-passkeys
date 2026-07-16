# browser-extensions

This folder is for browser-extension-specific passkey work, including shared browser code, samples, and track-specific experiments.

Relevant details can be brought in from existing browser-extension research, but reusable contracts and logic should be pushed toward `contracts/` and `shared/` when they become cross-track assets.

## Samples

- `keyvault-passkey-provider/` is the imported MV3 Key Vault authenticator spike. Its persistent side panel includes a development-only Function catalog adapter, context-aware login launch, and removal of Function-created records and their Key Vault signing keys.
- `TODO.md` records the deferred production broker design and its security requirements.
