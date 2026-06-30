# function-app

This folder is for Function App-specific samples and templates.

The current sample is:

- `powershell\keyvault-passkey-http`: PowerShell HTTP-triggered Functions + Bicep + Key Vault for TAP and ESTSAUTH passkey registration
- `python\keyvault-passkey-http`: Python HTTP-triggered Functions + Bicep + Key Vault for TAP and ESTSAUTH passkey registration

The goal is to keep Functions as a host surface, not as the owner of shared business logic:

- shared auth, Key Vault, and metadata helpers should live elsewhere
- Functions should provide trigger bindings, configuration, and deployment shape
