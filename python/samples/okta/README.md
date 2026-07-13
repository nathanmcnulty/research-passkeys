# Python Okta examples

These samples use the same two development paths as the PowerShell Okta track:

- `test_okta_myaccount_webauthn.py` starts `POST /idp/myaccount/webauthn/registration` with a user OAuth token.
- `passkey-register/register_okta_passkey_via_idx_session.py` enrolls a Key Vault-backed credential from a copied browser IDX session.
- `passkey-login/invoke_okta_passkey_login.py` starts a fresh username/IDX transaction and signs the assertion with Key Vault.
- `passkey-login/test_okta_passkey_login_via_idx_session.py` submits an assertion to a browser transaction that is paused before `/idp/idx/challenge/answer`.

Install the canonical library dependencies first (`azure-identity`, `cbor2`, `cryptography`, and `requests`). The scripts use `az login` for Key Vault access unless `--keyvault-access-token` is supplied.

Browser-session scripts accept short-lived Cookie and `stateHandle` values. Keep those values in memory, do not commit them, and delete/revoke the session after testing.

For the MyAccount script, use `--access-token` or configure a public OIDC client with `okta.myAccount.webauthn.manage` and pass `--client-id`.
