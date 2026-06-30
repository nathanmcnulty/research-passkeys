# Key Vault passkey HTTP Function sample (Python)

This sample hosts two Python HTTP-triggered Azure Functions that register passkeys with Azure Key Vault-backed credential keys:

- `RegisterPasskeyViaTap`: accepts `userPrincipalName` or `email` plus `tap`
- `RegisterPasskeyViaEstsAuth`: accepts `userPrincipalName` or `email` plus `estsAuth` or `estsAuthCookie`

Unlike the PowerShell sample, this version is **Python-native**. The function host and the TAP and ESTSAUTH registration flows run in Python instead of shelling out to PowerShell.

## Layout

- `src/`: Azure Functions Python v2 app plus a synced copy of the canonical `passkey` package
- `infra/`: Bicep deployment for Flex Consumption, managed identity, Key Vault, and monitoring
- `scripts/Sync-PasskeyLibrary.ps1`: refreshes the deployable `src\passkey` folder from `python\libraries\passkey`

## Runtime configuration

These app settings are expected:

- `PASSKEY_TENANT_ID`
- `PASSKEY_KEYVAULT_NAME`
- `PASSKEY_MANAGED_IDENTITY_CLIENT_ID`
- `PASSKEY_KEYVAULT_ACCESS_TOKEN` (optional local override; not used in Azure when managed identity is available)

## Local development

1. Copy `src/local.settings.sample.json` to `src/local.settings.json`.
2. Set `PASSKEY_TENANT_ID` and `PASSKEY_KEYVAULT_NAME`.
3. For local development, provide `PASSKEY_KEYVAULT_ACCESS_TOKEN`.
4. From `src/`, install dependencies and run the app:

   ```powershell
   ..\scripts\Sync-PasskeyLibrary.ps1
   pip install -r requirements.txt
   func start
   ```

## Request examples

TAP registration:

```json
{
  "userPrincipalName": "user@tenant.onmicrosoft.com",
  "tap": "replace-with-tap",
  "displayName": "Python Function App Passkey"
}
```

ESTSAUTH registration:

```json
{
  "userPrincipalName": "user@tenant.onmicrosoft.com",
  "estsAuth": "replace-with-estsauth-cookie",
  "displayName": "Python Function App Passkey"
}
```

The ESTSAUTH function rejects requests when the cookie resolves to a different user than the requested `userPrincipalName`.

## Deploy with Bicep

The Bicep sample targets subscription `a80941e8-c2b9-4bc9-83ad-117cc40d0bea` and defaults to `westus2`.

```powershell
az account set --subscription a80941e8-c2b9-4bc9-83ad-117cc40d0bea
az group create --name rg-passkey-func-python-sample-wus2 --location westus2
az deployment group what-if --resource-group rg-passkey-func-python-sample-wus2 --template-file infra/main.bicep
az deployment group create --resource-group rg-passkey-func-python-sample-wus2 --template-file infra/main.bicep
```

After infrastructure deployment, deploy the function code from `src/`.

For a one-command path from this repo, use:

```powershell
.\scripts\deployment\Deploy-FunctionSample.ps1 `
  -TemplateId python-keyvault-passkey-http `
  -ResourceGroupName rg-passkey-func-python-sample-wus2 `
  -EnvironmentName sample
```
