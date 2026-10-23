# Passkey research and code samples

Explore passkey registration, authentication, and Azure Key Vault-backed signing with PowerShell, Python, GitHub Actions, and Azure Functions. This repository collects reusable code, shared credential schemas, and focused examples for Microsoft Entra ID and Okta.

These are experimental research tools, not production-ready or FIDO-certified authenticators. Start with the guide for your scenario and review its security limitations before running code against an account or tenant.

## Find an example

| What you want to explore | Start here |
| --- | --- |
| Entra registration and login with PowerShell | [PowerShell guide](powershell/README.md) · [Standalone scripts](powershell/scripts/entra/reference) |
| Reusable Entra PowerShell commands | [Passkey module and build guide](powershell/BUILD.md) |
| Entra and Okta flows in Python | [Python guide](python/README.md) · [Entra samples](python/samples/entra) · [Okta samples](python/samples/okta) |
| Okta MyAccount and IDX flows in PowerShell | [Okta scripts](powershell/scripts/okta) |
| Passkey authentication in GitHub Actions | [Action guide](github/action-passkey-login/README.md) · [Enrollment and export adapters](github/adapters/README.md) |
| Hosted passkey experiments | [Azure Functions samples](function-app/README.md) |
| Automation and webhook integrations | [Azure Automation runbooks](azure-automation/function-passkey-runbooks) · [Logic App template](templates/logic-app/passkey-function-http) |
| Browser and Windows provider research | [Browser extension research](browser-extensions/README.md) · [Windows provider experiments](windows-passkey-provider/README.md) |

See the [examples matrix](docs/examples-matrix.md) for provider and language coverage. Some directories contain design notes or historical experiments rather than a maintained runnable implementation; their own guides explain the status.

## Before you run anything

- Use a dedicated test account and tenant. Registration, provisioning, and export commands can create authentication methods, persistent access, keys, or secrets. Read the command help and required permissions first.
- Protect credential files, private keys, TAPs, tokens, and session cookies. Never commit them or include them in logs. Use a private output directory, especially on Windows where files inherit its ACLs.
- Software-generated user-presence and user-verification flags do not prove a person was present or verified by an authenticator. Key Vault signing does not change that limitation. Tenant policy may reject these flows.
- Offline tests validate implementation contracts, not live service acceptance, deployed authentication, or hardware assurance. Historical device-code and imported browser-extension spikes are not supported starting points for current testing.
- Follow the [security baseline](docs/security/baseline.md) and the sample-specific guidance. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## PowerShell source and distributions

The maintained Entra commands live in [`powershell/src`](powershell/src), with standalone entrypoints in [`powershell/entrypoints`](powershell/entrypoints). A deterministic build produces self-contained scripts and the [`Passkey` module](powershell/modules/Passkey) from the same source.

Use the checked-in distributions directly, or follow [BUILD.md](powershell/BUILD.md) to develop and validate changes. These commands require PowerShell 7.6; the offline test baseline is Pester 6.2.0. Importing the module declares commands without authenticating or contacting a service.

```powershell
Import-Module ./powershell/modules/Passkey/Passkey.psd1
Get-Command -Module Passkey
Get-Help Register-EntraSoftwarePasskey -Full
```

The example above only loads the module and displays command information. Commands that register credentials, provision resources, or export secrets require their own explicit inputs and review.

## Repository guide

- [`contracts`](contracts): shared JSON schemas, including the [login credential contract](contracts/passkey-login-credential.schema.json).
- [`shared`](shared): cross-language helpers and design notes.
- [`powershell`](powershell) and [`python`](python): libraries, commands, and provider-specific samples.
- [`github`](github): Action distribution and enrollment/export adapters.
- [`function-app`](function-app), [`azure-automation`](azure-automation), and [`templates`](templates): hosted samples and integration starters.
- [`browser-extensions`](browser-extensions) and [`windows-passkey-provider`](windows-passkey-provider): provider-specific experiments and research.
- [`samples`](samples): scenario assets, including notification examples.
- [`scripts`](scripts): deployment, packaging, and validation helpers. Read their prerequisites before execution; some perform live operations.
- [`docs`](docs): [architecture](docs/architecture/repo-structure.md), [authentication contracts](docs/auth/passkey-login-contract.md), [Conditional Access](docs/auth/conditional-access.md), and [downstream consumption](docs/migration/downstream-consumption.md).

## Contributing and validation

Keep reusable behavior in maintained source and host-specific integration in its own sample. For Entra PowerShell changes, deliberately update the source version and commit regenerated distributions alongside the source. See [BUILD.md](powershell/BUILD.md) for the full workflow and credential-free test commands.

Describe what changed, which checks you ran, and which live scenarios remain unverified. Do not treat a passing offline suite as permission to deploy or enroll credentials.

## License

Project-authored source and documentation are released under the [Unlicense](UNLICENSE). Dependencies retain their own license terms.
