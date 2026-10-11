# GitHub secret adapters

Maintained functions live in `powershell/src/GitHub`, with enrollment using the shared
Entra registration flow. The files here are generated, self-contained distributions.
GitHub provides secret storage and CI transport; it is not a cryptographic signer.

See the [usage/build guide](../../powershell/BUILD.md) and [Action package](../action-passkey-login/README.md).

`Register-GitHubPasskeyViaTAP.ps1` requires consumers paused and explicit legacy
software-attestation acknowledgement. It verifies the expected registration before
export. `Export-PasskeyToGitHubSecret.ps1` can be dot-sourced to load functions, or
invoked with an explicit credential and repository. Four secret writes are not atomic;
private-key secret is written last. Inspect any partial failure before resuming consumers.
Use `-WhatIf` for no-I/O validation. No real credential is used by the offline tests.
