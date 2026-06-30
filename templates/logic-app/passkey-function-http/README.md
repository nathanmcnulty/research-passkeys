# Logic App passkey Function template

This starter deploys three **Consumption Logic Apps** that front the passkey Function endpoints:

- `register-via-tap`
- `register-via-estsauth`
- `login-with-passkey`

## Why this template exists

Logic Apps are a good orchestration surface when you want:

- a webhook entrypoint with request validation
- simple branching or approvals around passkey operations
- a serverless workflow that forwards payloads to the validated Function App surfaces

The workflow definitions intentionally stay thin. They forward request bodies to the Function endpoints rather than re-implementing passkey protocol logic in Logic Apps.

## Files

- `main.bicep`: deploys the Logic App workflows
- `main.parameters.sample.json`: sample deployment parameters
- `workflows\*.json`: workflow definitions loaded by the Bicep template

## Deploy

```powershell
az group create --name rg-passkey-logicapp-sample-wus2 --location westus2
az deployment group create `
  --resource-group rg-passkey-logicapp-sample-wus2 `
  --template-file .\main.bicep `
  --parameters .\main.parameters.sample.json
```

Set these parameters before deployment:

- `functionBaseUrl`
- `functionKey`

The `functionBaseUrl` should be the host root for one of the passkey Function samples, for example:

- `https://func-kvpk-example.azurewebsites.net`
