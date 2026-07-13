# Key Vault passkey HTTP Function sample (Python)

This sample hosts Python Azure Functions that register passkeys with Azure Key Vault-backed credential keys:

- `RegisterEntraPasskeyViaTap`: accepts `userPrincipalName` or `email` plus `tap`
- `RegisterEntraPasskeyViaEstsAuth`: accepts `userPrincipalName` or `email` plus `estsAuth`, `estsAuthCookie`, or a browser-exported cookie JSON blob containing `ESTSAUTH`
- `QueueEntraPasskeyRegistrationViaEstsAuth`: accepts the same ESTSAUTH inputs and enqueues registration work for async processing
- `ProcessEntraPasskeyRegistrationViaEstsAuth`: queue-triggered worker that runs the ESTSAUTH registration flow
- `GetEntraPasskeyRegistrationStatus`: reads queued Entra registration status
- `LoginWithEntraPasskey`: accepts a stored credential record and returns an ESTSAUTH cookie when passkey login succeeds
- `StartOktaMyAccountWebAuthnRegistration`: starts an Okta MyAccount WebAuthn ceremony from a user access token
- `RegisterOktaPasskeyViaIdxSession`: completes an Okta IDX browser-session registration with a Key Vault-backed credential
- `QueueOktaPasskeyRegistrationViaIdxSession`: enqueues an Okta IDX browser-session registration
- `ProcessOktaPasskeyRegistrationViaIdxSession`: queue-triggered worker for the Okta IDX registration flow
- `GetOktaPasskeyRegistrationStatus`: reads queued Okta registration status
- `LoginWithOktaPasskey`: starts a fresh Okta IDX login and signs the assertion with Key Vault
- `TestOktaPasskeyLoginViaIdxSession`: submits an assertion to an active Okta browser IDX transaction

Unlike the PowerShell sample, this version is **Python-native**. The function host and the TAP and ESTSAUTH registration flows run in Python instead of shelling out to PowerShell.

This sample uses the Azure Functions Python v2 decorator model, so the functions live in [src/function_app.py](/home/nathan/GitHub/research-passkeys/function-app/python/keyvault-passkey-http/src/function_app.py) instead of one folder per function. The runtime still exposes the same named functions as the PowerShell app.

## Layout

- `src/`: Azure Functions Python v2 app plus a synced copy of the canonical `passkey` package
- `infra/`: Bicep deployment for Flex Consumption, managed identity, Key Vault, and monitoring
- `scripts/Sync-PasskeyLibrary.ps1`: refreshes the deployable `src\passkey` folder (including Entra and Okta modules) from `python\libraries\passkey`

## Runtime configuration

These app settings are expected:

- `PASSKEY_TENANT_ID`
- `PASSKEY_KEYVAULT_NAME`
- `PASSKEY_MANAGED_IDENTITY_CLIENT_ID`
- `PASSKEY_KEYVAULT_ACCESS_TOKEN` (optional local override; not used in Azure when managed identity is available)
- `PASSKEY_REGISTRATION_QUEUE_NAME` (required for the async ESTSAUTH route; defaults to `passkey-registration` in the samples)
- `PASSKEY_OKTA_REGISTRATION_QUEUE_NAME` (required for the async Okta IDX route; defaults to `okta-passkey-registration`)
- `PASSKEY_OKTA_DOMAIN` (optional default for the Okta functions; requests may provide `oktaDomain`)
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

Post that payload to `/api/entra/passkeys/register/estsauth/queue` to return `202 Accepted` immediately and let the queue worker process registrations one at a time.

## Okta routes

- `POST /api/okta/passkeys/register/myaccount`: starts `POST /idp/myaccount/webauthn/registration`; provide a user-scoped Okta access token in `accessToken` or a Bearer header.
- `POST /api/okta/passkeys/register/idx`: completes an IDX browser-session registration using `cookieHeader`, `stateHandle`, `authenticatorId`, and Key Vault configuration.
- `POST /api/okta/passkeys/register/idx/queue`: queues the same IDX registration and returns an Okta status URL.
- `GET /api/okta/passkeys/register/status/{requestId}`: reads queued Okta registration status.
- `POST /api/okta/passkeys/login`: starts a fresh Okta IDX login from `userName` and a stored credential.
- `POST /api/okta/passkeys/login/idx`: submits an assertion to an active browser IDX transaction.

Queued Okta registration payload:

```json
{
  "oktaDomain": "your-tenant.okta.com",
  "cookieHeader": "replace-with-browser-cookie-header",
  "stateHandle": "replace-with-idx-state-handle",
  "authenticatorId": "auts...",
  "keyVaultKeyName": "optional-key-name",
  "transport": "usb"
}
```

The Okta queue uses its own `PASSKEY_OKTA_REGISTRATION_QUEUE_NAME` queue and carries browser cookies and an IDX `stateHandle`, so it should be processed immediately; both are short-lived secrets and may expire before a delayed worker starts. Do not use these browser-session routes as the production browser-extension protocol.

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
  -EnvironmentName sample `
  -OktaDomain your-org.okta.com
```
