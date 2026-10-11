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
Use `scripts\deployment\Deploy-FunctionSample.ps1 -SkipCodeDeploy` when you want to provision isolated infrastructure from this repo. Code publication requires a reviewed private deployment path; `-PushCodeThroughPrivateEndpoint` is an operator opt-in and does not itself verify connectivity.

### Shared Python code

Downstream Python repos should prefer `python\libraries\passkey` as the canonical source for:

- passkey registration logic
- passkey login logic
- Key Vault-backed signing helpers

Function-host repos that need a deployable in-repo copy can sync from the canonical library into host-specific folders, following the same pattern used by `function-app\python\keyvault-passkey-http\scripts\Sync-PasskeyLibrary.ps1`.

### Shared login credential contract

Downstream login consumers should target `contracts\passkey-login-credential.schema.json` so one stored credential record can be shared across:

- PowerShell passkey login
- Python passkey login
- future host wrappers that only need to load and pass through the stored credential

### Validation automation

For repeatable local validation, inspect and use only the applicable current flow:

- `scripts\validation\Invoke-EntraPasskeySmokeTest.ps1`

The Python and PowerShell device-code bootstrap files in the rename map above are historical source, not validation commands. Use cached WAM/MSAL or normal OS/browser sign-in for current Microsoft authentication.

### Automation and Logic App starters

For Azure-hosted orchestration layers, start from:

- `samples\azure-automation\function-passkey-runbooks`
- `templates\logic-app\passkey-function-http`

These assets intentionally call the Function surfaces instead of re-embedding passkey protocol logic in each orchestration host.


## Maintained GitHub and personal-repository mirrors

For this concrete source-sync flow, the authoritative mapping is
`scripts/sync/downstream-manifest.json`. See [personal-passkeys-map.md](personal-passkeys-map.md)
for each public entry point, imported versus updated status, and security boundaries.
All paths and SHA-256 values are explicit; the tool does not discover files by wildcard.
Unlisted downstream files are untouched. The historical DOCX is a documented exclusion.

With Python 3 and reviewed local checkouts under a common directory (one directory
named `nathanmcnulty` and one named `action-passkey-login`), run from research:

```sh
python scripts/sync/render_compatibility.py
python scripts/sync/render_compatibility.py --check
python scripts/sync/export_downstream.py --refresh-hashes
python -m unittest discover -s scripts/sync -p 'test_*.py'
python scripts/sync/export_downstream.py --target-root /path/to/checkouts --apply
python scripts/sync/export_downstream.py --target-root /path/to/checkouts --check
```

Review the canonical diff and refreshed manifest before applying. Hash refresh is a
maintainer operation, not evidence that new code was independently reviewed. The exporter
checks source hashes before any write, copies exact bytes, and removes only the explicitly
listed unpublished adapter files when their old hashes match. It does not commit, push,
merge, authenticate, dispatch workflows, or install scheduled sync. Use `--check` for
read-only drift detection. This manifest requires generated-compatibility validation: the exporter recomputes
the expected files with its sibling renderer and refuses stale files before export
or hash refresh. Run the separate renderer and tests after canonical runtime edits. Rendered personal logins must pass their compatibility tests,
the canonical action tests, and adapter tests with synthetic inputs only.

The action's four existing workflow files are inert nested source in research and retain
their downstream paths/behavior. No new GitHub permission or live test is introduced.
Cross-repository publication is not atomic: land/review source first and update downstream
mirrors from the same reviewed source revision. Record the research commit in downstream
PR descriptions; the manifest hashes identify exact file contents without a self-referential
commit field. Windows checkouts must preserve bytes (for example `core.autocrlf=false`)
because drift checks intentionally compare hashes, not normalized text.
