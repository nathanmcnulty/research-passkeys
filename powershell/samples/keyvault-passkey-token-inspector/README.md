# PowerShell Key Vault passkey token inspector

This local research sample wraps the existing Entra passkey login path, redeems the resulting ESTS session through OAuth authorization-code flow with PKCE, and inspects the returned OAuth/OIDC metadata.

The output includes token presence and length, decoded access-token and ID-token claims, cookie names and lengths, requested scopes, expiry, and token type. It never prints authorization codes, cookie values, or token values, including partial previews. Output from the wrapped login script is suppressed so its legacy cookie preview is not copied into inspector logs.

Decoded claims can contain personal and tenant information. Keep the output local and do not attach it to public issues or logs without reviewing it first.

## Usage

```powershell
pwsh .\Invoke-KeyVaultPasskeyTokenInspector.ps1 -KeyFilePath .\credential.json
```

The sample uses the repository's normal Az PowerShell or Azure CLI path to authorize Key Vault signing. Useful parameters include:

- `-UserPrincipalName`
- `-TenantId organizations`
- `-ClientId 04b07795-8ddb-461a-bbee-02f9e1bf7b46`
- `-RedirectUri msauth.com.msauth.unsignedapp://auth`
- `-Scope https://graph.microsoft.com/.default,openid,profile,offline_access`
- `-KeyVaultName`
- `-KeyVaultKeyName`
- `-KeyVaultTenantId`
- `-PassThru`

The default client ID and redirect URI are the public Azure CLI client values already used by the repository's Entra passkey login sample. SAML assertions are part of a separate federation flow and are not returned by this OAuth/OIDC sample.
