from __future__ import annotations

import json
import sys
from pathlib import Path

import azure.functions as func

_CANONICAL_LIBRARY_ROOT = Path(__file__).resolve().parents[4] / "python" / "libraries" / "passkey" / "src"
if _CANONICAL_LIBRARY_ROOT.exists():
    sys.path.insert(0, str(_CANONICAL_LIBRARY_ROOT))

from passkey import (
    PasskeySecurityError,
    PasskeyValidationError,
    authenticate_with_passkey,
    load_config_from_environment,
    register_passkey_via_ests_auth,
    register_passkey_via_tap,
)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _get_request_body(req: func.HttpRequest) -> dict[str, object]:
    try:
        body = req.get_json()
        if isinstance(body, dict):
            return body
    except ValueError:
        raw_body = req.get_body()
        if raw_body:
            try:
                parsed = json.loads(raw_body.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise PasskeyValidationError("Request body must be valid JSON.") from exc
            if isinstance(parsed, dict):
                return parsed
    return {}


def _get_request_value(body: dict[str, object], req: func.HttpRequest, *names: str) -> str | None:
    for name in names:
        value = body.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        query_value = req.params.get(name)
        if isinstance(query_value, str) and query_value.strip():
            return query_value.strip()
    return None


def _json_response(status_code: int, payload: dict[str, object]) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, separators=(",", ":")),
        status_code=status_code,
        mimetype="application/json",
    )


def _get_credential_payload(body: dict[str, object]) -> dict[str, object]:
    credential = body.get("credential")
    if isinstance(credential, dict):
        return dict(credential)

    return {
        key: value
        for key, value in body.items()
        if key not in {"credential", "authUrl", "keyVaultName", "keyVaultKeyName"}
    }


@app.function_name(name="RegisterPasskeyViaTap")
@app.route(route="passkeys/register/tap", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_passkey_via_tap_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        user_principal_name = _get_request_value(body, req, "userPrincipalName", "email")
        tap = _get_request_value(body, req, "tap", "temporaryAccessPass")
        display_name = _get_request_value(body, req, "displayName") or "Software Passkey"
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")

        credential = register_passkey_via_tap(
            config=config,
            user_principal_name=user_principal_name or "",
            tap=tap or "",
            display_name=display_name,
            key_vault_key_name=key_vault_key_name,
        )
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "tap",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="RegisterPasskeyViaEstsAuth")
@app.route(route="passkeys/register/estsauth", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_passkey_via_ests_auth_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        user_principal_name = _get_request_value(body, req, "userPrincipalName", "email")
        ests_auth = _get_request_value(body, req, "estsAuth", "estsAuthCookie")
        display_name = _get_request_value(body, req, "displayName", "passkeyDisplayName") or "Software Passkey"
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")

        credential = register_passkey_via_ests_auth(
            config=config,
            requested_user_principal_name=user_principal_name or "",
            ests_auth_cookie=ests_auth or "",
            display_name=display_name,
            key_vault_key_name=key_vault_key_name,
        )
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "estsauth",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="LoginWithPasskey")
@app.route(route="passkeys/login", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def login_with_passkey_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        auth_url = _get_request_value(body, req, "authUrl")
        key_vault_name = _get_request_value(body, req, "keyVaultName")
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")
        credential = _get_credential_payload(body)
        if not credential:
            raise PasskeyValidationError(
                "Request body must include a credential object or passkey login credential fields."
            )
        if key_vault_name or key_vault_key_name:
            existing_key_vault = credential.get("keyVault")
            credential["keyVault"] = dict(existing_key_vault) if isinstance(existing_key_vault, dict) else {}
            if key_vault_name:
                credential["keyVault"]["vaultName"] = key_vault_name
            if key_vault_key_name:
                credential["keyVault"]["keyName"] = key_vault_key_name

        login_kwargs = {
            "credential": credential,
            "key_vault_access_token": config.key_vault_access_token,
            "key_vault_managed_identity_client_id": config.managed_identity_client_id,
            "key_vault_tenant_id": config.tenant_id,
        }
        if auth_url:
            login_kwargs["auth_url"] = auth_url

        result = authenticate_with_passkey(**login_kwargs)
        return _json_response(
            200 if result.success else 401,
            {
                "success": result.success,
                "authMethod": "passkey",
                "userPrincipalName": result.user_principal_name,
                "signatureMethod": result.signature_method,
                "cookieType": result.cookie_type,
                "estsAuth": result.cookie_value,
                "estsAuthCookie": result.cookie_value,
                "keyVaultName": result.key_vault_name,
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})
