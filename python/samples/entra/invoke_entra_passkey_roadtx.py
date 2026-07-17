from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBRARY_ROOT = REPO_ROOT / "python" / "libraries" / "passkey" / "src"
if str(LIBRARY_ROOT) not in sys.path:
    sys.path.insert(0, str(LIBRARY_ROOT))


DEFAULT_ROADTX_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEFAULT_ROADTX_SCOPE = "https://graph.microsoft.com/.default"


def build_roadtx_command(args: argparse.Namespace, cookie_value: str) -> list[str]:
    command = [
        args.roadtx_command,
        "interactiveauth",
        "--estscookie",
        cookie_value,
        "--client",
        args.roadtx_client,
        "--tokenfile",
        args.roadtx_tokenfile,
    ]

    if args.roadtx_resource:
        command.extend(("--resource", args.roadtx_resource))
    else:
        command.extend(("--scope", args.roadtx_scope))

    optional_arguments = (
        ("--tenant", args.roadtx_tenant),
        ("--redirect-url", args.roadtx_redirect_url),
        ("--user-agent", args.roadtx_user_agent),
        ("--driver-path", args.roadtx_driver_path),
    )
    for name, value in optional_arguments:
        if value:
            command.extend((name, value))

    if args.roadtx_headless:
        command.append("--headless")
    if args.roadtx_keep_open:
        command.append("--keep-open")
    if args.roadtx_capture_code:
        command.append("--capture-code")
    if args.roadtx_tokens_stdout:
        command.append("--tokens-stdout")

    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate with a passkey, then hand the resulting ESTS cookie to roadtx."
    )
    parser.add_argument("--credential-path", required=True)
    parser.add_argument("--keyvault-name")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--keyvault-client-id")
    parser.add_argument("--keyvault-client-secret")
    parser.add_argument("--keyvault-tenant-id")
    parser.add_argument("--auth-url")
    parser.add_argument("--debug", action="store_true", help="Print safe HTTP/page/cookie diagnostics to stderr.")

    parser.add_argument("--roadtx-command", default="roadtx", help="roadtx executable or path to it.")
    parser.add_argument("--roadtx-client", default=DEFAULT_ROADTX_CLIENT)
    resource_group = parser.add_mutually_exclusive_group()
    resource_group.add_argument("--roadtx-scope", default=DEFAULT_ROADTX_SCOPE)
    resource_group.add_argument("--roadtx-resource")
    parser.add_argument("--roadtx-tenant")
    parser.add_argument("--roadtx-redirect-url")
    parser.add_argument("--roadtx-user-agent")
    parser.add_argument("--roadtx-driver-path")
    parser.add_argument("--roadtx-tokenfile", default=".roadtools_auth")
    parser.add_argument("--roadtx-headless", action="store_true")
    parser.add_argument("--roadtx-keep-open", action="store_true")
    parser.add_argument("--roadtx-capture-code", action="store_true")
    parser.add_argument("--roadtx-tokens-stdout", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    from passkey import authenticate_with_passkey, load_credential_record  # noqa: PLC0415

    credential = load_credential_record(
        credential_path=args.credential_path,
        key_vault_name=args.keyvault_name,
        key_vault_key_name=args.keyvault_key_name,
    )
    auth_arguments = {
        "credential": credential,
        "key_vault_access_token": args.keyvault_access_token,
        "key_vault_client_id": args.keyvault_client_id,
        "key_vault_client_secret": args.keyvault_client_secret,
        "key_vault_tenant_id": args.keyvault_tenant_id,
    }
    if args.auth_url:
        auth_arguments["auth_url"] = args.auth_url
    if args.debug:
        auth_arguments["debug"] = True

    result = authenticate_with_passkey(**auth_arguments)
    if not result.success or not result.cookie_value:
        print("Passkey authentication did not produce an ESTS cookie.", file=sys.stderr)
        return 1

    print(
        f"Passkey authentication succeeded for {result.user_principal_name}; "
        f"handing {result.cookie_type or 'ESTS'} cookie to roadtx.",
        file=sys.stderr,
    )
    command = build_roadtx_command(args, result.cookie_value)
    try:
        completed = subprocess.run(command, check=False)
    except FileNotFoundError:
        print(
            f"Could not find roadtx executable {args.roadtx_command!r}. "
            "Install roadtx or provide --roadtx-command.",
            file=sys.stderr,
        )
        return 127
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
