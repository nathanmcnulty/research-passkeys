# browser-extensions

This folder is for browser-extension-specific passkey work, including shared browser code, samples, and track-specific experiments.

Relevant details can be brought in from existing browser-extension research, but reusable contracts and logic should be pushed toward `contracts/` and `shared/` when they become cross-track assets.

## Samples

- `keyvault-passkey-provider/` is a historical imported MV3 spike. Its persistent side panel informed the maintained provider, but its experimental Function, UV, attestation, and User-Agent behavior must not be treated as current or production-safe.
- `TODO.md` records the deferred production broker design and its security requirements.

Security decisions for user presence and verification are recorded in `user-presence-and-verification.md`. The provider repository remains canonical; the snapshots below are provenance-locked inputs rather than independently maintained copies.

## Provider baselines and experiments

`vendor/key-vault-passkey-provider/` contains byte-for-byte, read-only snapshots of the canonical provider extension. `upstream-provider.lock.json` binds each snapshot to its provider commit, Git tree, version, extension identity, file list, sizes, and SHA-256 digests. Its embedded raw Git object proof links the pinned commit through the repository root and `src` trees to the vendored `browser-extension` tree without requiring cross-repository credentials. Run `node browser-extensions/scripts/validate-upstream-provider-lock.mjs` from the repository root to verify the full chain.

Do not edit a vendored snapshot. Put research-owned changes in a separately declared experiment directory and compose a beta build from the locked baseline plus that overlay. Promote one experiment at a time through a pull request in the provider repository; never copy the historical spike or a composed beta tree over the provider source.
