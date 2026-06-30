# PowerShell Key Vault passkey HTTP starter

Source sample:

- `function-app\powershell\keyvault-passkey-http`

Use this starter when a downstream repo needs:

- HTTP-triggered PowerShell Functions for TAP and ESTSAUTH passkey registration
- Bicep for Flex Consumption + managed identity + Key Vault
- synced PowerShell passkey assets from the canonical `powershell\` track

Export example:

```powershell
.\scripts\packaging\Export-FunctionTemplate.ps1 -TemplateId powershell-keyvault-passkey-http -DestinationPath C:\path\to\repo
```
