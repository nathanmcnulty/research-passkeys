from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def build_endpoint_url(explicit_url: str | None, base_url: str | None) -> str | None:
    if explicit_url:
        if "code" in parse.parse_qs(parse.urlsplit(explicit_url).query):
            raise ValueError("Function keys must be supplied in the x-functions-key header, not the URL.")
        return explicit_url

    if not base_url:
        return None

    return f"{base_url.rstrip('/')}/api/entra/passkeys/register/estsauth/queue"


def load_cookie_export(path: str | None, raw_json: str | None) -> Any | None:
    content = None
    if path:
        content = Path(path).read_text(encoding="utf-8")
    elif raw_json:
        content = raw_json

    if not content:
        return None

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return content


def resolve_ests_auth(direct_value: str | None, env_var_name: str, prompt: bool) -> str | None:
    if direct_value:
        return direct_value

    env_value = os.getenv(env_var_name)
    if env_value:
        return env_value

    if prompt:
        return getpass.getpass("Enter ESTSAUTH: ")

    return None


def invoke_queue_request(target: str, url: str, function_key: str | None, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if function_key:
        headers["x-functions-key"] = function_key
    req = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            status_url = parsed.get("statusUrl")
            if isinstance(status_url, str) and status_url.startswith("/"):
                parsed_base = parse.urlsplit(url)
                status_url = f"{parsed_base.scheme}://{parsed_base.netloc}{status_url}"
            return {
                "target": target,
                "attempted": True,
                "endpoint": url,
                "httpStatus": response.status,
                "success": bool(parsed.get("success")),
                "queued": bool(parsed.get("queued")),
                "requestId": parsed.get("requestId"),
                "queueName": parsed.get("queueName"),
                "userPrincipalName": parsed.get("userPrincipalName"),
                "statusUrl": status_url,
                "error": None,
            }
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        error_message = str(exc)
        try:
            parsed_error = json.loads(response_body) if response_body else {}
            if isinstance(parsed_error, dict) and parsed_error.get("error"):
                error_message = str(parsed_error["error"])
        except json.JSONDecodeError:
            pass

        return {
            "target": target,
            "attempted": True,
            "endpoint": url,
            "httpStatus": exc.code,
            "success": False,
            "queued": False,
            "requestId": None,
            "queueName": None,
            "userPrincipalName": payload.get("userPrincipalName"),
            "statusUrl": None,
            "error": error_message,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "target": target,
            "attempted": True,
            "endpoint": url,
            "httpStatus": None,
            "success": False,
            "queued": False,
            "requestId": None,
            "queueName": None,
            "userPrincipalName": payload.get("userPrincipalName"),
            "statusUrl": None,
            "error": str(exc),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit ESTSAUTH queue registration requests to the Function samples.")
    parser.add_argument("--user-principal-name", required=True)
    parser.add_argument("--display-name", default="Software Passkey")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--powershell-function-url")
    parser.add_argument("--python-function-url")
    parser.add_argument("--powershell-base-url")
    parser.add_argument("--python-base-url")
    parser.add_argument("--powershell-function-key")
    parser.add_argument("--python-function-key")
    parser.add_argument("--common-function-key")
    parser.add_argument("--ests-auth")
    parser.add_argument("--ests-auth-env-var", default="PASSKEY_ESTSAUTH")
    parser.add_argument("--cookie-export-path")
    parser.add_argument("--cookie-export-json")
    parser.add_argument("--prompt-for-ests-auth", action="store_true")
    parser.add_argument("--target", choices=("powershell", "python", "both"), default="both")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()

    cookie_export = load_cookie_export(args.cookie_export_path, args.cookie_export_json)
    ests_auth = None
    if cookie_export is None:
        ests_auth = resolve_ests_auth(args.ests_auth, args.ests_auth_env_var, args.prompt_for_ests_auth)
        if not ests_auth:
            parser.error(
                f"provide --ests-auth, set {args.ests_auth_env_var}, use --prompt-for-ests-auth, "
                "or provide --cookie-export-path/--cookie-export-json"
            )

    payload: dict[str, Any] = {
        "userPrincipalName": args.user_principal_name,
        "displayName": args.display_name,
    }
    if args.keyvault_key_name:
        payload["keyVaultKeyName"] = args.keyvault_key_name
    if cookie_export is not None:
        payload["cookieExport"] = cookie_export
    else:
        payload["estsAuth"] = ests_auth

    powershell_url = build_endpoint_url(
        args.powershell_function_url,
        args.powershell_base_url,
    )
    python_url = build_endpoint_url(
        args.python_function_url,
        args.python_base_url,
    )

    targets: list[dict[str, Any]] = []
    if args.target in {"powershell", "both"}:
        if not powershell_url:
            parser.error("PowerShell target selected, but no PowerShell function URL or base URL was provided.")
        targets.append(invoke_queue_request("powershell", powershell_url, args.powershell_function_key or args.common_function_key, payload, args.timeout_seconds))

    if args.target in {"python", "both"}:
        if not python_url:
            parser.error("Python target selected, but no Python function URL or base URL was provided.")
        targets.append(invoke_queue_request("python", python_url, args.python_function_key or args.common_function_key, payload, args.timeout_seconds))

    summary = {
        "submittedAtUtc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "userPrincipalName": args.user_principal_name,
        "usedCookieExport": cookie_export is not None,
        "targets": targets,
    }
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if all(target["success"] for target in targets) else 1


if __name__ == "__main__":
    raise SystemExit(main())
