# browser-extensions

This folder is for browser-extension-specific passkey work, including shared browser code, samples, and track-specific experiments.

Relevant details can be brought in from existing browser-extension research, but reusable contracts and logic should be pushed toward `contracts/` and `shared/` when they become cross-track assets.

## Samples

- `keyvault-passkey-provider/` is a historical imported MV3 spike. Its persistent side panel informed the maintained provider, but its experimental Function, UV, attestation, and User-Agent behavior must not be treated as current or production-safe.
- `TODO.md` records the deferred production broker design and its security requirements.

Security decisions for user presence and verification are recorded in `user-presence-and-verification.md`. This repository is the central tracker for extension implementation experiments, shared contracts, and promotion decisions. `keyvault-passkey-provider` is the consuming project and release source for accepted components. Its currently installed extension is the security baseline while research catches up; do not replace it with the older spike.

## Provider baselines and experiments

`vendor/key-vault-passkey-provider/` contains byte-for-byte, read-only snapshots of the provider extension. `upstream-provider.lock.json` binds the active snapshot to its provider commit, Git tree, version, extension identity, file list, sizes, and SHA-256 digests. Its embedded raw Git object proof links the pinned commit through the repository root and `src` trees to the vendored `browser-extension` tree without requiring cross-repository credentials. Run `node browser-extensions/scripts/validate-upstream-provider-lock.mjs` from the repository root to verify the full chain. The active development baseline is provider commit `9ffbe22f4b78ec8c5d1bb33fe719894dcd615eb5`; the earlier `dev-d7a6f35` snapshot remains preserved.

Do not edit a vendored snapshot. Put research-owned changes in a separately declared experiment directory and compose a beta build from the locked baseline plus that overlay. Promote one reviewed component at a time through a pull request in the provider repository, then refresh the locked baseline. The historical 40-file spike intentionally differs from the current 50-file provider extension; it remains beta evidence, not a tree to synchronize wholesale. The lock defines what must match byte-for-byte, while overlays declare intentional differences.

When the provider project changes its extension, refresh the research baseline from its exact merged commit using `node browser-extensions/scripts/refresh-upstream-provider-lock.mjs --provider-repo <provider-checkout> --commit <full-commit-sha>`. The command reads Git commit objects rather than working-tree files, preserves earlier snapshots, and validates the new lock. New shared implementation work should normally begin here as a bounded experiment or contract, then move into the provider project after review and relevant live evidence.
