# PowerShell device code bootstrap sample

This sample is the PowerShell counterpart to the Python device-code bootstrap. It keeps the delegated-auth bootstrap path local and CA-friendly by using Azure CLI device code flow first.

It uses:

- `az login --use-device-code` for interactive sign-in
- `az account get-access-token` to request a Microsoft Graph token
- JWT claim parsing in PowerShell to print a compact result summary

## Usage

```powershell
pwsh .\Invoke-EntraDeviceCodeBootstrap.ps1
```

Optional parameters:

- `-TenantId <tenant-id>`
- `-SubscriptionId <subscription-id>`
- `-ForceLogin`
- `-Scope https://graph.microsoft.com/.default`

This sample is intentionally local/CLI-first. It establishes the cleaner delegated bootstrap path before layering on additional passkey research flows.
