# Repository structure

## Goal

`research-passkeys` is allowed to collect material from multiple experiments, but it should remain curated instead of inheriting the layout of any single source repo.

## What belongs where

### `contracts/`

Language-neutral schemas and canonical model definitions:

- credential envelopes
- stored credential records
- configuration shapes that multiple hosts share

If a shape needs to be identical across PowerShell, .NET, TypeScript, Python, browser extensions, or Function Apps, define it here first.

### `shared/`

Cross-cutting logic and design notes that multiple tracks should consume:

- auth abstractions
- Key Vault interaction patterns
- WebAuthn helpers
- metadata protection and recovery patterns

`shared/` is the center of gravity for reusable concepts even when the implementation lives in multiple languages.

### Track folders

Track folders exist so experiments can stay explicit without flattening everything into one generic library layout:

- `powershell/`
- `browser-extensions/`
- `windows-passkey-provider/`
- `function-app/`
- `python/`

Track-specific code should stay in its track folder unless it becomes broadly reusable enough to promote into `shared/` and `contracts/`.

### `templates/` and `samples/`

- `templates/` contains publishable starters
- `samples/` contains focused end-to-end scenarios

Templates should be minimal and stable. Samples can be more opinionated and scenario-specific.

## Intake rules

When pulling code from existing repos:

1. Move shared shapes into `contracts/` first.
2. Move reusable logic into `shared/` or language-specific helper areas.
3. Keep host-specific code in the matching track folder.
4. Preserve compatibility-only or research-only flows, but label them clearly.

## Anti-patterns

- making the repo mirror one upstream project
- mixing raw host glue with shared contracts
- burying Conditional Access handling inside random scripts
- assuming downstream repos can move into this repo

## Surface parity rule

When a new flow is promoted beyond one-off research, the preferred shape is:

1. shared core logic in a canonical library or module
2. a local CLI or sample that exercises that shared core directly
3. a Function host adapter only when the scenario benefits from HTTP-triggered or hosted execution

This keeps host glue thin and makes parity gaps obvious.

### Current exception: device code bootstrap

Device code stays **local-first** by default. It is intentionally a CLI/bootstrap surface in both Python and PowerShell because it maps naturally to an interactive delegated-auth prompt. It should only grow a hosted variant if the design explicitly introduces a brokered callback or another server-side completion model.
