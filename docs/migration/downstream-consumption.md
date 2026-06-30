# Downstream consumption model

Other repos do not need to move into `research-passkeys` for this repo to become the source of truth.

## Supported consumption models

### Source sync

Good when a private or organization-owned repo needs exact source files from here:

- submodule
- subtree
- scripted copy/sync automation

Use this for shared scripts, templates, or code that must stay visible in the downstream repo.

### Package or artifact consumption

Good when the shared code can be versioned and consumed indirectly:

- PowerShell modules
- NuGet packages
- npm packages
- generated templates or release artifacts

Use this when the downstream repo should depend on a stable version instead of copying source.

### Selective pull model

Good when the downstream repo only needs a narrow subset:

- one schema
- one helper module
- one template
- one sample adapted into local code

## Guidance

1. Keep the canonical contract and guidance here.
2. Let each downstream repo choose the least disruptive consumption model.
3. Avoid assuming all consumers can use the same packaging or sync strategy.
4. Track compatibility notes in this repo so fixes can be propagated outward consistently.

## Concrete downstream starting points

### Function App starters

Downstream repos can now start from:

- `function-app\powershell\keyvault-passkey-http`
- `function-app\python\keyvault-passkey-http`

or from the publishable starter layer:

- `templates\function-app\powershell-keyvault-passkey-http`
- `templates\function-app\python-keyvault-passkey-http`

Use `scripts\packaging\Export-FunctionTemplate.ps1` to copy one of these starters into a downstream repo without importing the full repository structure.

### Shared Python code

Downstream Python repos should prefer `python\libraries\passkey` as the canonical source for:

- passkey registration logic
- passkey login logic
- Key Vault-backed signing helpers

Function-host repos that need a deployable in-repo copy can sync from the canonical library into host-specific folders, following the same pattern used by `function-app\python\keyvault-passkey-http\scripts\Sync-PasskeyLibrary.ps1`.
