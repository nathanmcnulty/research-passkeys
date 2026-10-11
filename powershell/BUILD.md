# Entra PowerShell: one source, two distributions

Requires PowerShell 7.6. The reviewed local runtime is 7.6.6 with Pester 6.2.0.
The scripts and module are experimental research tools; offline tests do not establish
live service acceptance or security certification.

## Use it

Download an individual script from `powershell/scripts/entra/reference` and run it.
Each file contains all required functions. There are no module dependencies or runtime
downloads of implementation code. SDKs are needed only by commands that explicitly use them.

```powershell
./powershell/scripts/entra/reference/Invoke-EntraPasskeyLogin.ps1 -KeyFilePath ./passkey.json -PassThru

Import-Module ./powershell/modules/Passkey/Passkey.psd1
Invoke-EntraPasskeyLogin -KeyFilePath ./passkey.json -PassThru
Get-Command -Module Passkey
```

Module import declares functions only. It does not authenticate, contact a service,
change caller defaults or leave credentials in global variables.

The public commands are:

- `Invoke-EntraPasskeyLogin`: local P-256 or versioned Key Vault signing
- `Register-EntraSoftwarePasskey`: Graph application-permission registration
- `Register-EntraSoftwarePasskeyViaTap` / `ViaEstsAuth`: native session registration
- `Register-EntraKeyVaultPasskey`, `ViaTap` / `ViaEstsAuth`: Key Vault native registration
- `Initialize-EntraPasskeyKeyVault`: explicit provisioning, including permission/secret creation
- `Register-GitHubPasskeyViaTAP`: verified enrollment then in-memory secret export
- `Export-PasskeyToGitHubSecret`: separate GitHub secret transport
- `Get-EntraEstsCookieViaTap`: secure TAP session-cookie retrieval
- `Get-EntraPasskeyMetadata`: informational, unverified metadata and connected Graph reads

Use `Get-Help <command> -Full` or `Get-Help <script-path> -Full` for inputs.
Registration/provisioning/export commands support `-WhatIf`, with no authentication,
network, enrollment, file or secret writes.

## Security and migration notes

- Legacy software login synthesizes UP/UV bits for compatibility. Neither a local key nor
  Key Vault signing proves fresh authenticator-bound user presence or verification.
  Results explicitly report `UserPresenceVerified=false` and `UserVerificationVerified=false`.
  Entra/Conditional Access policies may reject this flow. There is no automatic OAuth consent.
- Key Vault registration uses `none` attestation and AT-only flags. Native software enrollment
  retains explicitly acknowledged synthetic packed attestation. Graph software registration
  uses `none` attestation and documents its software-generated flags. None of these is a
  hardware-authenticator compliance claim. Premium vault capability does not make `kty=EC` HSM-backed.
- Login returns bearer cookies only with `-IncludeAuthenticationCookie`; module sessions only
  with `-IncludeAuthenticationSession`. The standalone-only `-PersistSessionToGlobalScope`
  replaces the named authentication globals, clearing stale identity before an attempt.
  Normal calls leave caller globals unchanged. The original named login aliases are retained;
  the two personal login URLs now share identical bytes, so use named arguments for portability.
- Provisioning can create persistent access and grant permissions. Read its help/confirmation
  before running. Creating a client secret requires `-PassThru` to return its unrecoverable
  value; otherwise use `-SkipSecret` or `-SkipServicePrincipal`. This guard runs before
  provisioning I/O. Default `-WhatIf` still previews without I/O. Secrets are not printed.
  Registration pipeline configuration retains SecureString secrets, not plaintext diagnostics.
- Software credential files are created without overwriting an existing file. Unix output is
  restricted to user read/write. On Windows, use a directory with a private inherited ACL.
  Credential write failure after enrollment is reported as partial completion, without silent rollback.
- GitHub export requires paused consumers. The four secret writes are non-atomic, with the
  private key written last. Do not resume consumers after a partial failure until you inspect it.
  Key Vault failure never falls back to a local signer. Metadata is informational and unverified.
- TAP helper credentials no longer have embedded defaults. Its default result contains a
  SecureString cookie; `-AsPlainText` explicitly restores the raw cookie-string output.

## Maintain and review

`powershell/src` contains complete functions and coherent protocol units:

- `Common`, `WebAuthn`: encoding, value/cookie boundaries and assertion construction
- `Local`, `KeyVault`: separate signing and provisioning responsibilities
- `Entra`: explicit registration/login request and state transitions
- `GitHub`: bounded CLI and secret transport
- `Public`: thin command orchestration with explicit inputs and returned context

`powershell/entrypoints` contains standalone help, parameters and invocation.
`build/targets.psd1` is the ordered, explicit source/file list and module export list.
Existing `Passkey.Common`, `Passkey.EntraAuth` and `Passkey.Broker` remain available for
unrelated callers; their shared browser-header/encoding behavior is covered by tests.

```powershell
./build/build.ps1
./build/build.ps1 -Check
./build/check-version.ps1 -BaseRef origin/main
Invoke-Pester .
```

Change maintained source, deliberately bump `build/VERSION`, build, and commit both source
and generated artifacts in the same PR. Version `0.1.0` is the first dual-build package;
it is independent of the Broker module and historical Action release versions. No tags or releases are changed. Later public source/build changes
require a strictly newer three-component version compared with the Git merge base.
Builds never increment versions or insert timestamps. Repeated unchanged builds are byte-identical.

`-Check` is read-only and rejects missing, stale and extra outputs, including untracked files,
plus orphan source/entrypoint files. Generated headers identify version and source paths.
CI uses credential-free mocks, a pinned PowerShell/Pester runtime, read-only repository access
and an always-running `passkey-ci` aggregate gate. It includes unrelated research tests.
A repository ruleset must separately require that check to enforce merge blocking.

## Exact downstream copies

Research owns source and generated output. Copy the reviewed bytes, never rebuild downstream.
Record the research commit and `build/VERSION` in each downstream PR/release description.
There is no automatic writer, second bot PR, compatibility tree or transformation renderer.

Personal repository paths under `Entra/passkeys/` map to these generated research files:

| Personal path | Research artifact |
| --- | --- |
| `PasskeyLogin.ps1` and `keyvault/PasskeyLogin.ps1` | `powershell/scripts/entra/reference/Invoke-EntraPasskeyLogin.ps1` |
| `Register-PasskeyViaTAP.ps1` | `powershell/scripts/entra/reference/Register-EntraSoftwarePasskeyViaTap.ps1` |
| `Register-PasskeyViaESTSAuth.ps1` | `powershell/scripts/entra/reference/Register-EntraSoftwarePasskeyViaEstsAuth.ps1` |
| `Get-ESTSAuthCookieViaTAP.ps1` | `powershell/scripts/entra/reference/Get-EntraEstsCookieViaTap.ps1` |
| `get-passkey-metadata.ps1` | `powershell/scripts/entra/reference/Get-EntraPasskeyMetadata.ps1` |
| `keyvault/Initialize-PasskeyKeyVault.ps1` | `powershell/scripts/entra/reference/Initialize-EntraPasskeyKeyVault.ps1` |
| `keyvault/New-KeyVaultPasskey.ps1` | `powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1` |
| `keyvault/Register-KeyVaultPasskeyViaTAP.ps1` | `powershell/scripts/entra/reference/Register-EntraKeyVaultPasskeyViaTap.ps1` |
| `keyvault/Register-KeyVaultPasskeyViaESTSAuth.ps1` | `powershell/scripts/entra/reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1` |

`github/action-passkey-login` maps directly to the Action repository with that prefix removed.
Its `PasskeyLogin.ps1` is byte-identical to the generated research login. Action inputs/output
masking and runner delivery stay in `action.yml`; GitHub is transport/CI, not a signer.

For local tests, set `POWERSHELL_TELEMETRY_OPTOUT=1` in the launching shell before
starting PowerShell; CI also asserts that engine telemetry is disabled.

The existing personal DOCX and unrelated public files remain unchanged. The three notification
assets map directly from `samples/notifications` to `Entra/passkeys/notifications`; they are
outside this passkey package's generated inventory.
