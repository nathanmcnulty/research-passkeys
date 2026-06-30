# Python Key Vault passkey HTTP starter

Source sample:

- `function-app\python\keyvault-passkey-http`

Use this starter when a downstream repo needs:

- HTTP-triggered Python Functions for TAP and ESTSAUTH passkey registration
- the canonical `python\libraries\passkey` library plus sync script
- Bicep for Flex Consumption + managed identity + Key Vault

Export example:

```powershell
.\scripts\packaging\Export-FunctionTemplate.ps1 -TemplateId python-keyvault-passkey-http -DestinationPath C:\path\to\repo
```
