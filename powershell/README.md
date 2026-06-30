# powershell

This folder now contains the first pass of the extracted PowerShell reference implementation from the existing `keyvault` scripts.

Current shape:

- `modules/Passkey.Common/`: shared binary and encoding helpers
- `modules/Passkey.EntraAuth/`: ESTS/TAP login helpers and browser-parity headers
- `scripts/reference/`: copied reference scripts from the original PowerShell repo
- `scripts/Register-KeyVaultPasskey.ps1`: curated registration wrapper that folds in proven fixes without copying the custom variant verbatim

Real fixes intentionally carried forward into the curated script include:

- automatic handling of the **Keep me signed in** interrupt
- requesting `ngcmfa` during the initial authorization-code exchange instead of waiting for a refresh-token retry
- browser-parity headers and better diagnostics around passkey-init and verification calls
- safer output/key-name sanitization for UPN-derived file and key names

Compatibility-only ESTS or raw session flows can still stay here, but they should be clearly labeled and separated from the preferred shared auth path.
