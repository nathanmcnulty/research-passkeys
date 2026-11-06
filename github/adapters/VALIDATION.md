# Offline validation

Run `Invoke-Pester ./tests` using PowerShell 7.6. Tests use synthetic keys and mock
Entra responses, and bounded fake CLI processes. They verify expected registration
before secret export, no writes on consent/state/verification failures, secret stdin
transport, partial-write reporting, timeout bounds and public entrypoints.

No live authentication, enrollment, secret upload or server acceptance is established.
See [the shared build/test guide](../../powershell/BUILD.md).
