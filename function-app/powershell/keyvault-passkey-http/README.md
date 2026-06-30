# Key Vault passkey HTTP Function sample

This sample hosts two PowerShell HTTP-triggered Azure Functions that create passkeys by invoking the repo's PowerShell passkey scripts:

- `RegisterPasskeyViaTap`: accepts `userPrincipalName`/`email` + `tap`
- `RegisterPasskeyViaEstsAuth`: accepts `userPrincipalName`/`email` + `estsAuth`/`estsAuthCookie`

The Function App uses:

- **Azure Functions Flex Consumption**
- **user-assigned managed identity**
- **Azure Key Vault** for key creation and signing
- **Bicep** for infrastructure

## Layout

- `src/`: Azure Functions project
- `infra/`: Bicep deployment
- `scripts/Sync-PasskeyAssets.ps1`: refreshes the bundled passkey scripts/modules from the repo's canonical PowerShell track

## Runtime configuration

These app settings are expected:

- `PASSKEY_TENANT_ID`
- `PASSKEY_KEYVAULT_NAME`
- `PASSKEY_MANAGED_IDENTITY_CLIENT_ID`
- `PASSKEY_KEYVAULT_ACCESS_TOKEN` (optional local override; not used in Azure when managed identity is available)

## Local development

1. Copy `src/local.settings.sample.json` to `src/local.settings.json`.
2. Set `PASSKEY_TENANT_ID` and `PASSKEY_KEYVAULT_NAME`.
3. For local development, provide `PASSKEY_KEYVAULT_ACCESS_TOKEN` because managed identity is not available locally.
4. Run from `src/`:

   ```powershell
   func start
   ```

## Request examples

TAP registration:

```json
{
  "userPrincipalName": "user@tenant.onmicrosoft.com",
  "tap": "replace-with-tap",
  "displayName": "Function App Passkey"
}
```

ESTSAUTH registration:

```json
{
  "userPrincipalName": "user@tenant.onmicrosoft.com",
  "estsAuth": "replace-with-estsauth-cookie",
  "displayName": "Function App Passkey"
}
```

The ESTSAUTH function rejects requests when the cookie resolves to a different user than the requested `userPrincipalName`.

## Deploy with Bicep

The Bicep sample targets subscription `a80941e8-c2b9-4bc9-83ad-117cc40d0bea` and defaults to `westus2`, which is available for the required resource types in this subscription.

Typical deployment flow:

```powershell
az account set --subscription a80941e8-c2b9-4bc9-83ad-117cc40d0bea
az group create --name rg-passkey-func-sample-wus2 --location westus2
az deployment group what-if --resource-group rg-passkey-func-sample-wus2 --template-file infra/main.bicep
az deployment group create --resource-group rg-passkey-func-sample-wus2 --template-file infra/main.bicep
```

After infra deployment, deploy the function code from `src/` with your preferred Functions deployment workflow.

For a one-command path from this repo, use:

```powershell
.\scripts\deployment\Deploy-FunctionSample.ps1 `
  -TemplateId powershell-keyvault-passkey-http `
  -ResourceGroupName rg-passkey-func-sample-wus2 `
  -EnvironmentName sample
```
