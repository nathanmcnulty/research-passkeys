# research-passkeys

Canonical passkey research and shared-code repo for consolidating passkey-related work across PowerShell, browser extensions, Windows provider experiments, Function App samples, and future languages such as Python.

This repo is meant to be the place where shared contracts, reusable helpers, templates, and reference guidance live. Other repos can stay where they are and consume changes from here through source sync, submodules, subtree pulls, or published packages/artifacts.

## Principles

- **Contract first**: shared data models and envelope formats belong here before host-specific implementations do.
- **Shared before host-specific**: reusable auth, Key Vault, WebAuthn, and metadata logic should converge here.
- **Explicit tracks**: browser-extension and Windows provider work live in named folders instead of defining the whole repo shape.
- **Conditional Access aware**: the standard auth path should handle claims challenges and KMSI consistently.
- **Downstream-friendly**: this repo should be easy for private and organization-owned repos to consume without moving into it.

## Repository layout

- `docs/architecture/`: repo shape, intake rules, and long-term structure
- `docs/auth/`: Conditional Access, KMSI, and auth-flow guidance
- `docs/security/`: security baselines and guardrails
- `docs/migration/`: downstream consumption and sync guidance
- `contracts/`: canonical JSON schemas and cross-language contracts
- `shared/`: host-agnostic helpers and design notes that multiple tracks should consume
- `powershell/`: PowerShell modules and thin command/script wrappers
- `browser-extensions/`: browser-extension-specific code and samples
- `windows-passkey-provider/`: Windows provider experiments, packaging, and host-specific code
- `function-app/`: Function App-specific samples and templates
- `python/`: future Python libraries and samples
- `templates/`: publishable starters
- `samples/`: end-to-end scenarios and walkthroughs

## Source material being consolidated

- `nathanmcnulty\Entra\passkeys\keyvault`: current PowerShell reference implementation
- `key-vault-passkey-provider`: source for relevant browser-extension and Windows provider details that should be selectively absorbed into this repo

## First milestone

1. Establish the repo skeleton and guidance docs.
2. Define canonical credential contracts.
3. Extract PowerShell helpers into reusable modules.
4. Add a Function App sample/template.
5. Start pulling in browser-extension and Windows provider details under their own track folders.
