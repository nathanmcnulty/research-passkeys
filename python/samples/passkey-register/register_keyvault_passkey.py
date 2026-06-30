from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBRARY_ROOT = REPO_ROOT / "python" / "libraries" / "passkey" / "src"
if str(LIBRARY_ROOT) not in sys.path:
    sys.path.insert(0, str(LIBRARY_ROOT))

from passkey import (  # noqa: E402
    PasskeyAppConfig,
    PasskeySecurityError,
    PasskeyValidationError,
    load_config_from_environment,
    register_passkey_via_ests_auth,
    register_passkey_via_tap,
)


def resolve_config(args: argparse.Namespace) -> PasskeyAppConfig:
    base = None
    try:
        base = load_config_from_environment()
    except PasskeyValidationError:
        if not args.tenant_id or not args.keyvault_name:
            raise

    return PasskeyAppConfig(
        tenant_id=args.tenant_id or (base.tenant_id if base else ""),
        key_vault_name=args.keyvault_name or (base.key_vault_name if base else ""),
        managed_identity_client_id=args.managed_identity_client_id
        or (base.managed_identity_client_id if base else None),
        key_vault_access_token=args.keyvault_access_token or (base.key_vault_access_token if base else None),
    )


def write_credential(credential: dict[str, object], output_path: str | None) -> str | None:
    if not output_path:
        return None

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(credential, indent=2), encoding="utf-8")
    return str(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a Key Vault-backed passkey from a local Python CLI.")
    parser.add_argument("--tenant-id")
    parser.add_argument("--keyvault-name")
    parser.add_argument("--managed-identity-client-id")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--user-principal-name", required=True)
    parser.add_argument("--display-name", default="Software Passkey")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--output-path")

    subparsers = parser.add_subparsers(dest="mode", required=True)

    tap_parser = subparsers.add_parser("tap", help="Register by using a Temporary Access Pass.")
    tap_parser.add_argument("--tap", required=True)

    ests_auth_parser = subparsers.add_parser("estsauth", help="Register by using an ESTSAUTH cookie.")
    ests_auth_parser.add_argument("--ests-auth", required=True)

    args = parser.parse_args()
    config = resolve_config(args)

    try:
        if args.mode == "tap":
            credential = register_passkey_via_tap(
                config=config,
                user_principal_name=args.user_principal_name,
                tap=args.tap,
                display_name=args.display_name,
                key_vault_key_name=args.keyvault_key_name,
            )
        else:
            credential = register_passkey_via_ests_auth(
                config=config,
                requested_user_principal_name=args.user_principal_name,
                ests_auth_cookie=args.ests_auth,
                display_name=args.display_name,
                key_vault_key_name=args.keyvault_key_name,
            )
    except (PasskeyValidationError, PasskeySecurityError) as exc:
        print(json.dumps({"success": False, "error": str(exc)}, separators=(",", ":")))
        return 1

    saved_path = write_credential(credential, args.output_path)
    print(
        json.dumps(
            {
                "success": True,
                "authMethod": args.mode,
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "outputPath": saved_path,
                "credential": credential,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
