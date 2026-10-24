# Passkey Login Action

> Maintained source: [research-passkeys/github/action-passkey-login](https://github.com/nathanmcnulty/research-passkeys/tree/main/github/action-passkey-login). The standalone action repository is the distribution mirror. Propose source changes in research, then copy its reviewed built artifacts. This remains a legacy experimental software-signing action; it does not establish authenticator-bound presence or verification.

Reusable GitHub Action for Entra passkey authentication whose primary purpose is to return an ESTS cookie for downstream tools. The safest supported design is to keep the passkey signing key in Azure Key Vault, authenticate the workflow to Azure with `azure/login`, and let this action return the cookie as a masked output.

## Repository layout

- Runtime action files stay in the repository root:
  - `action.yml`
  - `PasskeyLogin.ps1`
  - `README.md`
- Optional onboarding material lives outside the runtime surface:
  - `examples/` for sanitized passkey JSON templates
  - `scripts/` for one-time setup helpers

Most users only need the workflow example in this README plus the action inputs. The `examples/` and `scripts/` folders are optional setup aids.

## Security model

This repository now treats security as the primary design goal.

Recommended path:

1. Store the passkey signing key in Azure Key Vault.
2. Use GitHub OIDC with `azure/login` so the workflow does not need a long-lived Azure client secret.
3. Store only passkey metadata in GitHub, no key material.
4. The action masks and exports the authenticated ESTS cookie by default because that is its primary purpose.

Less preferred path:

1. Supply `private-key` directly for local testing or tightly controlled scenarios.
2. Do not commit passkey JSON or private keys to the repository.
3. Expect the action to warn when it falls back to a local private key.

## Configuration rule

The passkey values must come from the same registration.

- `credential-id`
- `user-handle`
- `user-principal-name`
- `key-vault-name`
- `key-vault-key-name`

Do not mix the `credential-id` from one passkey with the Key Vault key from another. That mismatch is easy to create during testing and is hard to spot from masked workflow logs.

If you test both signing modes, keep two distinct secret sets when they come from different passkey registrations:

- Key Vault-backed test values for the Key Vault workflow
- Private-key test values for the private-key workflow

## What should be stored where

Suggested GitHub Environment storage:

| Item | Store as | Notes |
| --- | --- | --- |
| `credential-id` | Secret | Unique identifier of the passkey. |
| `user-handle` | Secret | Unique identifier of the user. |
| `user-principal-name` | Secret or variable | Use one approach consistently within a workflow. |
| `key-vault-name` | Secret or variable | Configuration only. The included workflows use secrets for simplicity. |
| `key-vault-key-name` | Secret or variable | Configuration only. The included workflows use secrets for simplicity. |
| `key-vault-tenant-id` | Secret or variable | Configuration only. |
| Azure OIDC client ID | Secret or variable | Used by `azure/login`. |
| `private-key` | Secret only if you must use local signing | Common for testing, but less secure than Key Vault. |

## Inputs

Required in all modes:

- `credential-id`
- `user-handle`
- `user-principal-name`

Key Vault mode, recommended:

- `key-vault-name`
- `key-vault-key-name`
- `key-vault-tenant-id` optional
- `key-vault-access-token` optional
- `key-vault-client-id` optional fallback
- `key-vault-client-secret` optional fallback

Local key mode, fallback:

- `private-key`

Optional behavior:

- `auth-url`
- `proxy`
- `export-auth-cookie` default `true`

## Outputs

- `authenticated`
- `cookie-name`
- `user-principal-name`
- `signature-method`
- `key-vault-name`
- `auth-cookie` populated by default unless `export-auth-cookie: false`

`auth-cookie` is masked before being written as an output, but it is still sensitive session material. The action prefers `ESTSAUTH` when available because that is the default cookie this action is intended to return.

## Recommended workflow

This is the default model the action is designed for. Configure the OIDC trust for the consuming repository and the `entra-prod` environment using [Minimal OIDC setup](#minimal-oidc-setup). Protect that environment with appropriate reviewers and deployment branch restrictions; do not remove it to make a branch-only trust work.

```yaml
name: Passkey Login

on:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

env:
  POWERSHELL_TELEMETRY_OPTOUT: '1'
  DOTNET_CLI_TELEMETRY_OPTOUT: '1'

jobs:
  passkey-login:
    runs-on: windows-latest
    environment: entra-prod

    steps:
      - uses: actions/checkout@v6

      - name: Verify installed PowerShell 7.6
        shell: pwsh
        run: |
          Write-Host "Installed PowerShell: $($PSVersionTable.PSVersion) ($([Environment]::ProcessPath))"
          if ($PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion.Minor -ne 6) {
            throw "Expected installed PowerShell 7.6, got $($PSVersionTable.PSVersion)."
          }
          if ([Microsoft.PowerShell.Telemetry.ApplicationInsightsTelemetry]::CanSendTelemetry) {
            throw 'Telemetry must be disabled before PowerShell starts.'
          }

      - name: Azure login via OIDC
        uses: azure/login@v3
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          allow-no-subscriptions: true

      - name: Passkey login
        id: passkey
        uses: nathanmcnulty/action-passkey-login@v1
        with:
          credential-id: ${{ secrets.PASSKEY_CREDENTIAL_ID }}
          user-handle: ${{ secrets.PASSKEY_USER_HANDLE }}
          user-principal-name: ${{ secrets.PASSKEY_USER_PRINCIPAL_NAME }}
          key-vault-name: ${{ secrets.PASSKEY_KEY_VAULT_NAME }}
          key-vault-key-name: ${{ secrets.PASSKEY_KEY_VAULT_KEY_NAME }}
          key-vault-tenant-id: ${{ secrets.AZURE_TENANT_ID }}

      - name: Use login result
        shell: pwsh
        env:
          ESTS_COOKIE: ${{ steps.passkey.outputs.auth-cookie }}
        run: |
          if ('${{ steps.passkey.outputs.authenticated }}' -ne 'true') {
            throw 'Passkey authentication did not complete successfully.'
          }

          "Authenticated user: ${{ steps.passkey.outputs.user-principal-name }}"
          "Signature method: ${{ steps.passkey.outputs.signature-method }}"
          "Cookie type: ${{ steps.passkey.outputs.cookie-name }}"

          if ([string]::IsNullOrWhiteSpace($env:ESTS_COOKIE)) {
            throw 'Expected auth-cookie output to be present.'
          }
```

## Using the ESTS cookie downstream

The action exports the ESTS cookie by default because that is the main artifact it produces. If you want to disable that output for testing, set `export-auth-cookie: false`.

Example using the cookie with a downstream PowerShell flow. This action is designed to return `ESTSAUTH`, so downstream validation should use the emitted `cookie-name` output instead of assuming `ESTSAUTHPERSISTENT`.

```yaml
      - name: Passkey login
        id: passkey
        uses: nathanmcnulty/action-passkey-login@v1
        with:
          credential-id: ${{ secrets.PASSKEY_CREDENTIAL_ID }}
          user-handle: ${{ secrets.PASSKEY_USER_HANDLE }}
          user-principal-name: ${{ secrets.PASSKEY_USER_PRINCIPAL_NAME }}
          key-vault-name: ${{ secrets.PASSKEY_KEY_VAULT_NAME }}
          key-vault-key-name: ${{ secrets.PASSKEY_KEY_VAULT_KEY_NAME }}

      - name: Downstream use of cookie
        shell: pwsh
        env:
          ESTS_COOKIE: ${{ steps.passkey.outputs.auth-cookie }}
          ESTS_COOKIE_NAME: ${{ steps.passkey.outputs.cookie-name }}
          TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: |
          if ([string]::IsNullOrWhiteSpace($env:ESTS_COOKIE)) {
            throw 'Expected auth-cookie output to be present.'
          }

          if ($env:ESTS_COOKIE_NAME -ne 'ESTSAUTH') {
            throw "Expected ESTSAUTH but received '$($env:ESTS_COOKIE_NAME)'."
          }

          ./scripts/Test-XdrConnectionByEstsCookie.ps1 `
            -EstsCookieValue $env:ESTS_COOKIE `
            -EstsCookieName $env:ESTS_COOKIE_NAME `
            -TenantId $env:TENANT_ID
```

Do not print the cookie. Do not promote it to an artifact. Keep its use scoped to the smallest possible set of steps.

For a repository-hosted login and portal-bootstrap exercise, use [test-xdr-key-vault.yml](.github/workflows/test-xdr-key-vault.yml). It signs in with the action, asserts that the returned cookie is `ESTSAUTH`, and exercises the portal form exchange at `security.microsoft.com`. Portal cookies, including anonymous tracking cookies, do not prove authenticated XDR access. The helper returns `BootstrapCompleted = true`, `ValidationScope = PortalBootstrapOnly`, and `AuthenticationVerified = false`; its legacy `Success` field remains false. A green run proves only these bounded checks, not an authenticated XDR readback or a specific tenant identity. Do not use it as an XDR authentication-validation badge.

## Local key mode

This is expected to be common during early testing or read-only automation, but it is still less secure than Key Vault-backed signing.

```yaml
      - name: Passkey login with local key
        uses: nathanmcnulty/action-passkey-login@v1
        with:
          credential-id: ${{ secrets.PASSKEY_CREDENTIAL_ID }}
          user-handle: ${{ secrets.PASSKEY_USER_HANDLE }}
          user-principal-name: ${{ secrets.PASSKEY_USER_PRINCIPAL_NAME }}
          private-key: ${{ secrets.PASSKEY_PRIVATE_KEY }}
```

If both a complete Key Vault configuration and `private-key` are provided, the action uses Key Vault and ignores the private key.

## Private repo testing

The repository does not need to be public for testing.

You can test this action in the same private repository by using a local path reference:

```yaml
      - name: Passkey login from same repo
        id: passkey
        uses: ./
        with:
          credential-id: ${{ secrets.PASSKEY_CREDENTIAL_ID }}
          user-handle: ${{ secrets.PASSKEY_USER_HANDLE }}
          user-principal-name: ${{ secrets.PASSKEY_USER_PRINCIPAL_NAME }}
          private-key: ${{ secrets.PASSKEY_PRIVATE_KEY }}
```

That is the simplest way to validate the action before making the repository public. Once you want other repositories to consume it, publish a tag such as `v1` and reference `owner/action-passkey-login@v1`.

For Key Vault-backed testing in this same repository, use the included workflow [test-key-vault.yml](.github/workflows/test-key-vault.yml) and configure these repository secrets first:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `PASSKEY_CREDENTIAL_ID`
- `PASSKEY_USER_HANDLE`
- `PASSKEY_USER_PRINCIPAL_NAME`
- `PASSKEY_KEY_VAULT_NAME`
- `PASSKEY_KEY_VAULT_KEY_NAME`

The workflow signs into Azure with `azure/login`, invokes the local action with Key Vault inputs, and verifies that the action reports `Azure Key Vault` as the signature method.

For local private-key testing in this same repository, use [test-private-key.yml](.github/workflows/test-private-key.yml) and configure a separate private-key passkey registration with these repository secrets:

- `PASSKEY_PRIVATE_CREDENTIAL_ID`
- `PASSKEY_PRIVATE_USER_HANDLE`
- `PASSKEY_PRIVATE_USER_PRINCIPAL_NAME`
- `PASSKEY_PRIVATE_KEY`

Do not point the private-key workflow at the Key Vault-backed registration values. The `credential-id`, `user-handle`, and `private-key` must all belong to the same passkey registration.

## Local script testing

For local testing outside GitHub Actions, create your own passkey JSON file and keep it out of source control. The repository includes sanitized examples for the expected shape:

- [examples/passkey.private-key.example.json](examples/passkey.private-key.example.json)
- [examples/passkey.keyvault.example.json](examples/passkey.keyvault.example.json)

Example:

```powershell
./PasskeyLogin.ps1 -KeyFilePath ./my-passkey.json -PassThru
```

The script no longer writes token previews to the console. It only includes the authenticated cookie value in its returned object when `-IncludeAuthenticationCookie` is specified.

## Notes

- The action bundles `PasskeyLogin.ps1` and requires PowerShell 7.6. Hosted and self-hosted runners must have it installed before invoking the action; preflight fails clearly on an older runtime. This action does not install or download its implementation at runtime.
- The action masks sensitive inputs before invoking the script.
- `azure/login` should run before this action when using Key Vault-backed signing.
- If you grant Key Vault data-plane access, use a role or permission set that allows signing but no broader secret access than necessary.

## Minimal OIDC setup

The repository includes [scripts/Setup-GitHubActionServicePrincipal.ps1](scripts/Setup-GitHubActionServicePrincipal.ps1), a helper that:

- creates or reuses an Entra app registration and its service principal
- creates or reuses one GitHub Actions federated credential with matching subject, issuer, and audience
- optionally grants `Key Vault Crypto User` on a specified Key Vault

It does not assign API permissions or create secrets. Run it with PowerShell 7.6 and an Azure CLI session in the intended tenant. Running it can create Azure resources and grant Key Vault access, so verify the target tenant, application, repository, and subject first.

`-GitHubRepo` is required and must identify **your consuming workflow repository**, not this sample or the action's publisher. Omitting it fails before any Azure CLI call. `-AppName` defaults to `action-passkey-login`; choose a distinct name if workflows should not share an application and its permissions.

### Match the job's actual subject

For the recommended workflow above, use `-Environment 'entra-prod'`, not a branch subject. A job that references a GitHub environment has an environment subject even when it runs from `main`. Entra requires an exact, case-sensitive match. Environment protection rules, not a branch suffix in the subject, control which branches can use that environment.

Check the consuming repository's Actions OIDC settings and the expected job `sub` before provisioning. GitHub supports both name-only subjects and [immutable subjects containing owner and repository IDs](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims). Newly created, renamed, or transferred repositories may use the immutable format. The helper does not query GitHub or infer the format from a repository name.

For a repository verified to use the name-only format, replace `<your-owner>/<your-workflow-repo>` and run:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo '<your-owner>/<your-workflow-repo>' -Environment 'entra-prod'
```

To also grant the Key Vault role:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo '<your-owner>/<your-workflow-repo>' -Environment 'entra-prod' -KeyVaultName '<your-key-vault-name>'
```

For the immutable format, supply both verified numeric IDs. These illustrative IDs must be replaced with your repository's actual values:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/automation' -GitHubOwnerId '123456' -GitHubRepositoryId '456789' -Environment 'entra-prod'
# Expected subject: repo:contoso@123456/automation@456789:environment:entra-prod
```

Alternatively, pass the exact verified subject, including any customized job context. The helper accepts a subject beginning with the specified repository's `repo:` segment, with both immutable IDs or neither; it rejects subjects for another repository. It preserves the supplied subject exactly and does not independently attest its IDs or GitHub configuration:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo 'contoso/automation' -OidcSubject 'repo:contoso@123456/automation@456789:environment:entra-prod'
```

`-Branch`, `-Environment`, and `-OidcSubject` are mutually exclusive. The default `-Branch 'main'` is only for a non-pull-request job that has no environment, with a verified name-only subject unless both immutable IDs are supplied. For example:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo '<your-owner>/<your-workflow-repo>' -Branch 'main'
```

When constructing an environment or branch subject, the helper encodes metadata colons as `%3A`, as specified by [GitHub's subject-claim reference](https://docs.github.com/en/actions/reference/security/oidc#example-subject-claims). An explicit `-OidcSubject` must already contain the exact encoding. Subjects customized without a leading repository segment require separate, carefully scoped provisioning rather than this helper.

### Safe reruns

The credential name is a fixed-length SHA-256 digest of the exact subject, issuer, and audience, so different repositories and contexts do not collide through shortened names or slash replacement. Existing credentials are reused only when all three trust properties match exactly. An incompatible credential with the same generated name or subject stops setup before a Key Vault role grant. The helper never deletes or replaces credentials; review conflicts manually. It also leaves unrelated and older name-based credentials unchanged, so review obsolete trust separately when migrating.

The fixed issuer is `https://token.actions.githubusercontent.com` and the sole audience is `api://AzureADTokenExchange`, matching this workflow's Azure login. See [Entra's federated credential requirements](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust) for exact matching and service limits.

After running the helper, store the emitted client and tenant IDs as GitHub secrets or variables to match your workflow. If you did not pass `-KeyVaultName`, grant the service principal `Key Vault Crypto User` on the target Key Vault or key separately. A successful setup does not verify a live token exchange or passkey login.

The OIDC setup helper refuses ambiguous application display-name matches before selecting a service principal or changing trust. Choose a unique `AppName`; it never selects the first of several matching registrations.

## Publishing

Tag a release such as `v1.0.0` and publish through the GitHub Marketplace flow in repository settings.

Application-intent confirmation (`CmsiInterrupt`/AADSTS50199) is separate from OAuth permission consent. The action stops at this confirmation by default. For an operator-authorized automation, set `confirm-application: 'true'` and `expected-client-id` to the intended authorization client; the initial URL must contain that client exactly once. This does not approve OAuth scope consent. The default Azure CLI authorization uses its HTTPS native callback. Assertions, identity response bodies, and credential prefixes are omitted from diagnostics.

Microsoft describes this app confirmation in its [AADSTS50199 documentation](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes).

## Proposed live validation

The [protected lab controller](docs/LAB-COOKIE-CONTROLLER.md) prepares a manual,
exact-revision cookie-output and server-backed session-reuse integration test.
It requires a separately reviewed public-client compatibility configuration with identity-only
permissions. Source and offline tests are not evidence of a passing live run.
Setup, controller bootstrap, hosted CI, merges and one bounded dispatch require
appropriate approval. Same-runner results are not hostile-candidate attestation.

The [live validation plan](docs/LIVE-VALIDATION-PLAN.md) describes the remaining
publication/setup/run sequence. No XDR access is established by this lane.
