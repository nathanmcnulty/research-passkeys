# Python Key Vault passkey token inspector

This local research sample uses an existing Key Vault-backed passkey credential to complete an Entra sign-in, redeem the resulting ESTS session through OAuth authorization-code flow with PKCE, and inspect the returned OAuth/OIDC metadata.

The output includes token presence and length, decoded access-token and ID-token claims, cookie names and lengths, requested scopes, expiry, and token type. It never prints authorization codes, cookie values, or token values, including partial previews.

Decoded claims can contain personal and tenant information. Keep the output local and do not attach it to public issues or logs without reviewing it first.

## Usage

Install the library dependencies, then run the sample:

```powershell
pip install -e ..\..\libraries\passkey
python .\inspect_keyvault_passkey_tokens.py --credential-path .\credential.json
```

The sample uses the repository's normal Azure CLI/Azure Identity path to authorize Key Vault signing. Useful options include:

- `--user-principal-name`
- `--tenant-id organizations`
- `--client-id 04b07795-8ddb-461a-bbee-02f9e1bf7b46`
- `--redirect-uri msauth.com.msauth.unsignedapp://auth`
- `--scope "https://graph.microsoft.com/.default openid profile offline_access"`
- `--keyvault-name`
- `--keyvault-key-name`
- `--keyvault-tenant-id`

The default client ID and redirect URI are the public Azure CLI client values already used by the repository's Entra passkey login sample. SAML assertions are part of a separate federation flow and are not returned by this OAuth/OIDC sample.
