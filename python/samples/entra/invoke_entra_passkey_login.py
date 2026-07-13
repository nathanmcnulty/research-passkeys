from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBRARY_ROOT = REPO_ROOT / "python" / "libraries" / "passkey" / "src"
if str(LIBRARY_ROOT) not in sys.path:
    sys.path.insert(0, str(LIBRARY_ROOT))

from passkey import authenticate_with_passkey, load_credential_record  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticate with a Key Vault-backed passkey credential.")
    parser.add_argument("--credential-path", required=True)
    parser.add_argument("--keyvault-name")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--keyvault-client-id")
    parser.add_argument("--keyvault-client-secret")
    parser.add_argument("--keyvault-tenant-id")
    parser.add_argument("--auth-url")
    args = parser.parse_args()

    credential = load_credential_record(
        credential_path=args.credential_path,
        key_vault_name=args.keyvault_name,
        key_vault_key_name=args.keyvault_key_name,
    )
    result = authenticate_with_passkey(
        credential=credential,
        key_vault_access_token=args.keyvault_access_token,
        key_vault_client_id=args.keyvault_client_id,
        key_vault_client_secret=args.keyvault_client_secret,
        key_vault_tenant_id=args.keyvault_tenant_id,
        auth_url=args.auth_url or None or "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    )

    print(
        json.dumps(
            {
                "success": result.success,
                "userPrincipalName": result.user_principal_name,
                "signatureMethod": result.signature_method,
                "cookieType": result.cookie_type,
                "estsAuthCookie": result.cookie_value,
                "keyVaultName": result.key_vault_name,
            },
            separators=(",", ":"),
        )
    )
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
