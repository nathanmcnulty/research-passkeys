# powershell

See [`docs/examples-matrix.md`](../docs/examples-matrix.md) for the cross-language/provider
parity matrix and provider-explicit naming map.

This folder now contains the first pass of the extracted PowerShell reference implementation from the existing `keyvault` scripts.

Current shape:

- `modules/Passkey.Common/`: shared binary and encoding helpers
- `modules/Passkey.EntraAuth/`: ESTS/TAP login helpers and browser-parity headers
- `modules/Passkey.Broker/`: Function-key client for Graph and Az PowerShell token handoff
- `scripts/entra/`: Entra registration, login, TAP/ESTSAUTH, and reference scripts
- `scripts/okta/`: Okta MyAccount and IDX registration/login proof-of-concept scripts
- `samples/entra/device-code-bootstrap/`: CA-friendly delegated-auth bootstrap using Azure CLI device code flow

Real fixes intentionally carried forward into the curated script include:

- automatic handling of the **Keep me signed in** interrupt
- requesting `ngcmfa` during the initial authorization-code exchange instead of waiting for a refresh-token retry
- browser-parity headers and better diagnostics around passkey-init and verification calls
- safer output/key-name sanitization for UPN-derived file and key names

Compatibility-only ESTS or raw session flows can still stay here, but they should be clearly labeled and separated from the preferred shared auth path.

## Passkey broker client

The PowerShell Function sample can exchange a stored Entra passkey assertion for a narrowly scoped Microsoft Graph or Azure Resource Manager token:

```powershell
Import-Module .\modules\Passkey.Broker\Passkey.Broker.psd1
$functionKey = Read-Host 'Function key' -AsSecureString
Connect-PasskeyBroker -Uri 'https://func-example.azurewebsites.net' -FunctionKey $functionKey

Get-PasskeyBrokerContext
Get-PasskeyRecord -RecordId '<record-id>'
Connect-MgGraphWithPasskey -RecordId '<record-id>' -Scopes 'User.Read'
Connect-AzAccountWithPasskey -RecordId '<record-id>' -SubscriptionId '<subscription-id>'
```

`Microsoft.Graph.Authentication` and `Az.Accounts` are optional client-side dependencies used only by their corresponding convenience commands. `Get-PasskeyAccessToken` always performs a new passkey authentication; the broker does not return or retain refresh tokens.

For Defender portal testing, the existing stored-login endpoint still returns an ESTSAUTH cookie with no-store response headers. That cookie can be passed to XdrInternals `Connect-XdrByEstsCookie`. Portal cookie bootstrapping remains provider-specific and is intentionally not part of `Passkey.Broker`.

## Okta MyAccount API smoke test

Create a public OIDC application in Okta, add `http://127.0.0.1:8765/callback/` as a sign-in redirect URI, and grant it `okta.myAccount.webauthn.manage` on the **Okta API Scopes** tab. Then run:

```powershell
.\scripts\okta\Test-OktaMyAccountWebAuthn.ps1 -OktaDomain 'your-org.okta.com' -ClientId '<client-id>'
```

The script uses authorization code + PKCE and only starts a short-lived WebAuthn registration ceremony. It does not create a Key Vault key or enroll a passkey.

For an end-to-end login test using the existing developer-tenant account-settings client:

```powershell
.\scripts\okta\Invoke-OktaPasskeyLogin.ps1 `
  -OktaDomain 'your-tenant.okta.com' `
  -UserName 'user@tenant.onmicrosoft.com' `
  -CredentialFilePath '.\okta-passkey-okta-pk-usershar-948352.json'
```

If the sign-in policy requires the password before exposing the passkey challenge:

```powershell
$password = Read-Host 'Okta password' -AsSecureString
.\scripts\okta\Invoke-OktaPasskeyLogin.ps1 `
  -OktaDomain 'your-tenant.okta.com' -UserName 'user@tenant.onmicrosoft.com' `
  -Password $password -CredentialFilePath '.\okta-passkey-okta-pk-usershar-948352.json'
```

The credential file is optional. The same test can use the credential ID and Key Vault coordinates directly:

```powershell
.\scripts\okta\Invoke-OktaPasskeyLogin.ps1 `
  -OktaDomain 'your-tenant.okta.com' `
  -UserName 'user@tenant.onmicrosoft.com' `
  -CredentialId 'OH_Dt-qTY2zcnRJo3z-aKKyA0jh47bqpQRfBsrtPETc' `
  -KeyVaultName 'kvpkarmxxd6byvwqw' `
  -KeyVaultKeyName 'okta-pk-usershar-948352' `
  -KeyVaultKeyId 'https://kvpkarmxxd6byvwqw.vault.azure.net/keys/okta-pk-usershar-948352/690c232db4f94a259456981fa2a5d011' `
  -SignCount 4
```

If the sign-in policy requires the password first, add it without placing the password in shell history:

```powershell
$password = Read-Host 'Okta password' -AsSecureString
.\scripts\okta\Invoke-OktaPasskeyLogin.ps1 `
  -OktaDomain 'your-tenant.okta.com' -UserName 'user@tenant.onmicrosoft.com' `
  -CredentialId 'OH_Dt-qTY2zcnRJo3z-aKKyA0jh47bqpQRfBsrtPETc' `
  -KeyVaultName 'kvpkarmxxd6byvwqw' -KeyVaultKeyName 'okta-pk-usershar-948352' `
  -KeyVaultKeyId 'https://kvpkarmxxd6byvwqw.vault.azure.net/keys/okta-pk-usershar-948352/690c232db4f94a259456981fa2a5d011' `
  -SignCount 4 `
  -Password $password
```

The script obtains a Key Vault access token from the current `Connect-AzAccount` or `az login` session; `-KeyVaultAccessToken` is available when a token is already in memory.
The default assertion counter is 1; increment `-SignCount` for repeated tests against the same enrollment.

## Okta IDX handoff POC

For rapid development testing without an OIDC application, `Register-OktaKeyVaultPasskeyViaIdxSession.ps1` accepts a current browser IDX `stateHandle`, Cookie header, and WebAuthn authenticator ID after the user has completed normal Okta step-up in the browser. It imports the Cookie header once into a PowerShell `WebRequestSession` and automatically retains any cookie updates returned by Okta. These values are credentials; don't save them or use this approach as the extension's production design.

To keep the Cookie header and state handle out of shell history, pass `SecureString` values:

```powershell
$cookie = Read-Host 'Copy the browser Cookie header' -AsSecureString
$state = Read-Host 'Copy the IDX stateHandle' -AsSecureString
.\scripts\okta\Register-OktaKeyVaultPasskeyViaIdxSession.ps1 `
  -OktaDomain 'your-org.okta.com' -CookieHeader $cookie -StateHandle $state `
  -AuthenticatorId 'auts...' -KeyVaultName 'your-key-vault'
```

After registration, begin a fresh Okta sign-in and select the WebAuthn authenticator. Pause before `/idp/idx/challenge/answer`, then copy the challenge and state handle from the active transaction and run. The login POC also imports the Cookie header once into a PowerShell `WebRequestSession`:

```powershell
$cookie = Read-Host 'Copy the browser Cookie header' -AsSecureString
$state = Read-Host 'Copy the IDX stateHandle' -AsSecureString
.\scripts\okta\Test-OktaPasskeyLoginViaIdxSession.ps1 `
  -OktaDomain 'your-org.okta.com' -CookieHeader $cookie -StateHandle $state `
  -Challenge '<base64url challenge>' -CredentialFilePath '.\okta-passkey-record.json'
```
