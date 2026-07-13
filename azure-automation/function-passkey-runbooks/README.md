# Azure Automation Function runbook samples

These runbooks are thin PowerShell adapters over the HTTP Function surfaces in this repo. They are a good fit when you want:

- scheduled or operator-started registration workflows
- an Azure-hosted control plane without copying the full passkey scripts into Automation
- the same Function-hosted contract used by Logic Apps or other orchestration layers

## Included runbooks

- `RegisterEntraPasskeyViaTap.Runbook.ps1`
- `RegisterEntraPasskeyViaEstsAuth.Runbook.ps1`
- `LoginWithEntraPasskey.Runbook.ps1`

## Suggested Automation assets

- store the Function key in an **encrypted Automation variable** or retrieve it from Key Vault
- keep the Function App URL in a normal Automation variable
- use a **PowerShell 7.4** runbook runtime when possible

## Runtime model

Each runbook:

1. accepts a Function base URL and Function key
2. builds the expected request body
3. calls the matching Function endpoint
4. returns the response body as JSON or as a PowerShell object with `-PassThru`

These runbooks intentionally keep the hosted logic thin. The passkey protocol logic remains in the canonical local and Function surfaces.
