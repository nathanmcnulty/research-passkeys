# GitHub integration source ownership

This directory is the maintained source for the GitHub adapters and the separately distributed GitHub Action. Edit here first; update downstream repositories through the reviewed offline sync described in [downstream consumption](../docs/migration/downstream-consumption.md).

- [adapters](adapters/README.md): experimental TAP registration and in-memory GitHub secret export, tests, and an inert workflow example. These live only in research; the unpublished personal-repository additions were relocated here.
- [action-passkey-login](action-passkey-login/README.md): the **complete** maintained action package, including action metadata, scripts, examples, tests, license, and workflow definitions. It is exported to `nathanmcnulty/action-passkey-login` without rewriting files.
- [legacy public entry points](../compatibility/nathanmcnulty/Entra/passkeys/README.md): the original personal repository URLs remain available as explicit compatibility mirrors.

## Security and execution boundaries

The action and adapters retain legacy experimental software signing/attestation behavior. Software UP/UV claims are not fresh authenticator-bound presence or verification, and passing offline tests does not prove enrollment acceptance, login support, or authenticator compliance. The adapter requires explicit legacy-flow opt-in. Historical scripts are not newly security-certified.

This package is separate from the guarded `powershell/scripts/entra/reference` and Function/browser research surfaces. Their deliberate software-assertion denial and attestation-removal boundaries remain unchanged. Do not import the action into those guarded implementations to bypass their refusal.

All action workflows are stored below `github/action-passkey-login/.github/workflows`, so they are inert in the research repository. The sync copies the already-existing workflows into the action repository; it adds no schedule, permission, secret, dispatch, deployment, or synchronization service. Existing authentication workflows must not be run as offline tests.
