# Key Vault passkey HTTP Function sample (Python)

This sample hosts Python Azure Functions that register passkeys with Azure Key Vault-backed credential keys:

- `RegisterPasskeyViaTap`: accepts `userPrincipalName` or `email` plus `tap`
- `RegisterPasskeyViaEstsAuth`: accepts `userPrincipalName` or `email` plus `estsAuth`, `estsAuthCookie`, or a browser-exported cookie JSON blob containing `ESTSAUTH`
- `QueuePasskeyRegistrationViaEstsAuth`: accepts the same ESTSAUTH inputs and enqueues registration work for async processing
- `ProcessPasskeyRegistrationViaEstsAuth`: queue-triggered worker that runs the ESTSAUTH registration flow
- `LoginWithPasskey`: accepts a stored credential record and returns an ESTSAUTH cookie when passkey login succeeds

Unlike the PowerShell sample, this version is **Python-native**. The function host and the TAP and ESTSAUTH registration flows run in Python instead of shelling out to PowerShell.

This sample uses the Azure Functions Python v2 decorator model, so the functions live in [src/function_app.py](/home/nathan/GitHub/research-passkeys/function-app/python/keyvault-passkey-http/src/function_app.py) instead of one folder per function. The runtime still exposes the same named functions as the PowerShell app.

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
- `PASSKEY_REGISTRATION_QUEUE_NAME` (required for the async ESTSAUTH route; defaults to `passkey-registration` in the samples)
- `AzureWebJobsFeatureFlags=EnableWorkerIndexing` (required for the Python v2 decorator model to index functions consistently)

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

Queued ESTSAUTH registration from a browser cookie export:

```json
{
  "userPrincipalName": "user@tenant.onmicrosoft.com",
  "cookieExport": "[{\"path\":\"/\",\"domain\":\".login.microsoftonline.com\",\"value\":\"replace-with-estsauth-cookie\",\"name\":\"ESTSAUTH\"}]",
  "displayName": "Python Function App Passkey"
}
```

Post that payload to `/api/passkeys/register/estsauth/queue` to return `202 Accepted` immediately and let the queue worker process registrations one at a time.

Passkey login:

```json
{
  "credential": {
    "credentialId": "replace-with-credential-id",
    "relyingParty": "login.microsoft.com",
    "url": "https://login.microsoft.com",
    "userName": "user@tenant.onmicrosoft.com",
    "userHandle": "replace-with-user-handle",
    "keyVault": {
      "vaultName": "replace-with-vault-name",
      "keyName": "replace-with-key-name"
    }
  }
}
```

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
