# browser-extensions

This folder is for browser-extension-specific passkey work, including shared browser code, samples, and track-specific experiments.

Relevant details can be brought in from existing browser-extension research, but reusable contracts and logic should be pushed toward `contracts/` and `shared/` when they become cross-track assets.

## Samples

- `keyvault-passkey-provider/` is a historical imported MV3 spike. Its persistent side panel informed the maintained provider, but its experimental Function, UV, attestation, and User-Agent behavior must not be treated as current or production-safe.
- `TODO.md` records the deferred production broker design and its security requirements.

Security decisions for user presence and verification are recorded in `user-presence-and-verification.md`. The implementation remains canonical in the provider repository rather than being duplicated here.
