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

This is the default model the action is designed for.

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

For a full repository-hosted validation flow, use [test-xdr-key-vault.yml](.github/workflows/test-xdr-key-vault.yml). It signs in with the action, asserts that the returned cookie is `ESTSAUTH`, and then validates that the cookie can bootstrap a session to `security.microsoft.com`.

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

## Minimal OIDC Setup

The repository includes [scripts/Setup-GitHubActionServicePrincipal.ps1](scripts/Setup-GitHubActionServicePrincipal.ps1), a minimal helper that:

- creates or reuses an Entra app registration
- creates or reuses its service principal
- creates one GitHub Actions federated credential for a branch
- optionally grants `Key Vault Crypto User` on a specified Key Vault

It does not assign API permissions or create secrets. That keeps the setup small and aligned with this action's use of `azure/login` plus Key Vault signing.

Example:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1
```

To create the OIDC objects and grant the Key Vault role in one step:

```powershell
./scripts/Setup-GitHubActionServicePrincipal.ps1 -KeyVaultName '<your-key-vault-name>'
```

After running it, store the emitted values as GitHub secrets or variables to match your workflow style. If you did not pass `-KeyVaultName`, grant the service principal `Key Vault Crypto User` on the target Key Vault or key separately.

## Publishing

Tag a release such as `v1.0.0` and publish through the GitHub Marketplace flow in repository settings.

Application-intent confirmation (`CmsiInterrupt`/AADSTS50199) is separate from OAuth permission consent. The action stops at this confirmation by default. For an operator-authorized automation, set `confirm-application: 'true'` and `expected-client-id` to the intended authorization client; the initial URL must contain that client exactly once. This does not approve OAuth scope consent. The default Azure CLI authorization uses its HTTPS native callback. Assertions, identity response bodies, and credential prefixes are omitted from diagnostics.

Microsoft describes this app confirmation in its [AADSTS50199 documentation](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes).
