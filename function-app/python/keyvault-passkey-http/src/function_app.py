from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import azure.functions as func
import requests
from azure.identity import ManagedIdentityCredential

_resolved_path = Path(__file__).resolve()
_CANONICAL_LIBRARY_ROOT = None
if len(_resolved_path.parents) > 4:
    _CANONICAL_LIBRARY_ROOT = _resolved_path.parents[4] / "python" / "libraries" / "passkey" / "src"
if _CANONICAL_LIBRARY_ROOT and _CANONICAL_LIBRARY_ROOT.exists():
    sys.path.insert(0, str(_CANONICAL_LIBRARY_ROOT))

from passkey import (
    PasskeySecurityError,
    PasskeyValidationError,
    authenticate_with_passkey,
    build_display_name,
    extract_ests_auth_cookie_value,
    load_config_from_environment,
    normalize_redirect_uri,
    normalize_user_agent,
    register_passkey_via_ests_auth,
    register_passkey_via_tap,
)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
_COOKIE_EXPORT_FIELDS = ("cookies", "cookieExport", "cookieJson", "cookieData", "browserCookies", "tokens")
_STATUS_CONTAINER_CACHE: set[str] = set()


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


def _get_body_value(body: dict[str, object], *names: str) -> object | None:
    for name in names:
        if name in body:
            return body[name]
    return None


def _resolve_user_agent(body: dict[str, object], req: func.HttpRequest) -> str:
    return normalize_user_agent(_get_request_value(body, req, "userAgent", "useragent"))


def _resolve_redirect_uri(body: dict[str, object], req: func.HttpRequest) -> str:
    return normalize_redirect_uri(_get_request_value(body, req, "redirectUri", "redirecturi"))


def _json_response(status_code: int, payload: dict[str, object]) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, separators=(",", ":")),
        status_code=status_code,
        mimetype="application/json",
    )


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _storage_rfc1123_timestamp() -> str:
    return datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _get_post_registration_login_delay_seconds() -> int:
    raw_value = os.getenv("PASSKEY_POST_REGISTRATION_LOGIN_DELAY_SECONDS", "10").strip()
    try:
        return max(0, int(raw_value))
    except ValueError:
        return 10


def _build_login_propagation_hint() -> dict[str, object]:
    return {
        "delaySeconds": _get_post_registration_login_delay_seconds(),
        "note": (
            "Newly registered passkeys can take a few seconds before login succeeds. "
            "If you automate login immediately after registration, wait briefly and retry once."
        ),
    }


def _get_storage_blob_service_uri() -> str:
    blob_service_uri = os.getenv("AzureWebJobsStorage__blobServiceUri", "").strip().rstrip("/")
    if not blob_service_uri:
        raise PasskeyValidationError("Missing required setting 'AzureWebJobsStorage__blobServiceUri'.")
    return blob_service_uri


def _get_status_container_name() -> str:
    return (os.getenv("PASSKEY_REGISTRATION_STATUS_CONTAINER_NAME", "passkey-registration-status").strip() or
            "passkey-registration-status").lower()


def _get_storage_access_token() -> str:
    client_id = os.getenv("PASSKEY_MANAGED_IDENTITY_CLIENT_ID") or None
    try:
        credential = ManagedIdentityCredential(client_id=client_id)
        return credential.get_token("https://storage.azure.com/.default").token
    except Exception:  # noqa: BLE001
        pass

    cli_command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        "https://storage.azure.com/",
        "--query",
        "accessToken",
        "-o",
        "tsv",
    ]
    try:
        result = subprocess.run(cli_command, capture_output=True, text=True, check=True)
        token = result.stdout.strip()
        if token:
            return token
    except Exception:  # noqa: BLE001
        pass

    raise PasskeyValidationError(
        "Unable to acquire a Storage access token. Run in Azure with managed identity or sign in with Azure CLI."
    )


def _build_storage_headers(access_token: str, **extra_headers: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "x-ms-version": "2023-11-03",
        "x-ms-date": _storage_rfc1123_timestamp(),
    }
    headers.update(extra_headers)
    return headers


def _ensure_status_container_exists() -> None:
    container_name = _get_status_container_name()
    if container_name in _STATUS_CONTAINER_CACHE:
        return

    response = requests.put(
        f"{_get_storage_blob_service_uri()}/{container_name}?restype=container",
        headers=_build_storage_headers(_get_storage_access_token()),
        timeout=30,
    )
    if response.status_code not in (201, 202, 409):
        raise PasskeyValidationError(
            f"Failed to ensure registration status container '{container_name}': "
            f"HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    _STATUS_CONTAINER_CACHE.add(container_name)


def _build_status_blob_url(request_id: str) -> str:
    return f"{_get_storage_blob_service_uri()}/{_get_status_container_name()}/{quote(f'{request_id}.json', safe='')}"


def _write_registration_status(request_id: str, payload: dict[str, object]) -> None:
    _ensure_status_container_exists()
    payload = dict(payload)
    payload.setdefault("requestId", request_id)
    payload["updatedAtUtc"] = _utc_timestamp()
    payload.setdefault("loginPropagation", _build_login_propagation_hint())
    response = requests.put(
        _build_status_blob_url(request_id),
        headers=_build_storage_headers(
            _get_storage_access_token(),
            **{
                "x-ms-blob-type": "BlockBlob",
                "Content-Type": "application/json; charset=utf-8",
            },
        ),
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        timeout=30,
    )
    if response.status_code not in (200, 201):
        raise PasskeyValidationError(
            f"Failed to write registration status '{request_id}': "
            f"HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )


def _read_registration_status(request_id: str) -> dict[str, object] | None:
    response = requests.get(
        _build_status_blob_url(request_id),
        headers=_build_storage_headers(_get_storage_access_token()),
        timeout=30,
    )
    if response.status_code == 404:
        return None
    if not response.ok:
        raise PasskeyValidationError(
            f"Failed to read registration status '{request_id}': "
            f"HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )
    if not response.text:
        return None
    return json.loads(response.text)


def _build_status_url(req: func.HttpRequest, request_id: str) -> str:
    base_url = req.url.split("?", 1)[0].rstrip("/")
    queue_suffix = "/api/passkeys/register/estsauth/queue"
    if base_url.endswith(queue_suffix):
        status_url = f"{base_url[: -len(queue_suffix)]}/api/passkeys/register/status/{request_id}"
    else:
        status_url = f"/api/passkeys/register/status/{request_id}"
    code = req.params.get("code")
    if code:
        separator = "&" if "?" in status_url else "?"
        status_url = f"{status_url}{separator}code={quote(code, safe='')}"
    return status_url


def _resolve_ests_auth_value(body: dict[str, object], req: func.HttpRequest) -> str | None:
    direct_cookie = _get_request_value(body, req, "estsAuth", "estsAuthCookie")
    if direct_cookie:
        parsed_direct_cookie = extract_ests_auth_cookie_value(direct_cookie)
        if parsed_direct_cookie:
            return parsed_direct_cookie

    cookie_source = _get_body_value(body, *_COOKIE_EXPORT_FIELDS)
    if cookie_source is not None:
        parsed_cookie = extract_ests_auth_cookie_value(cookie_source)
        if parsed_cookie:
            return parsed_cookie

    cookie_query_value = _get_request_value(body, req, *_COOKIE_EXPORT_FIELDS)
    if cookie_query_value:
        return extract_ests_auth_cookie_value(cookie_query_value)

    return None


def _build_registration_queue_message(
    *,
    user_principal_name: str,
    ests_auth_cookie: str,
    display_name: str,
    key_vault_key_name: str | None,
    user_agent: str,
    redirect_uri: str,
) -> dict[str, object]:
    return {
        "requestId": str(uuid.uuid4()),
        "queuedAtUtc": _utc_timestamp(),
        "authMethod": "estsauth",
        "userPrincipalName": user_principal_name,
        "displayName": display_name,
        "keyVaultKeyName": key_vault_key_name,
        "estsAuth": ests_auth_cookie,
        "userAgent": normalize_user_agent(user_agent),
        "redirectUri": normalize_redirect_uri(redirect_uri),
    }


def _process_registration_queue_message(message_payload: dict[str, object]) -> dict[str, object]:
    user_principal_name = str(message_payload.get("userPrincipalName") or "").strip()
    ests_auth_cookie = str(message_payload.get("estsAuth") or message_payload.get("estsAuthCookie") or "").strip()
    display_name = str(message_payload.get("displayName") or message_payload.get("passkeyDisplayName") or "").strip()
    key_vault_key_name = str(message_payload.get("keyVaultKeyName") or "").strip() or None
    user_agent = normalize_user_agent(message_payload.get("userAgent") or message_payload.get("useragent"))
    redirect_uri = normalize_redirect_uri(message_payload.get("redirectUri") or message_payload.get("redirecturi"))

    if not user_principal_name:
        raise PasskeyValidationError("Queue message is missing 'userPrincipalName'.")
    if not ests_auth_cookie:
        raise PasskeyValidationError("Queue message is missing 'estsAuth'.")

    config = load_config_from_environment()
    credential = register_passkey_via_ests_auth(
        config=config,
        requested_user_principal_name=user_principal_name,
        ests_auth_cookie=ests_auth_cookie,
        display_name=display_name or build_display_name(),
        key_vault_key_name=key_vault_key_name,
        user_agent=user_agent,
        redirect_uri=redirect_uri,
    )
    return {
        "requestId": str(message_payload.get("requestId") or ""),
        "userPrincipalName": user_principal_name,
        "keyVaultName": config.key_vault_name,
        "credential": credential,
    }


def _get_credential_payload(body: dict[str, object]) -> dict[str, object]:
    credential = body.get("credential")
    if isinstance(credential, dict):
        return dict(credential)

    return {
        key: value
        for key, value in body.items()
        if key not in {"credential", "authUrl", "keyVaultName", "keyVaultKeyName", "userAgent", "useragent", "redirectUri", "redirecturi"}
    }


@app.function_name(name="RegisterPasskeyViaTap")
@app.route(route="passkeys/register/tap", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_passkey_via_tap_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        user_principal_name = _get_request_value(body, req, "userPrincipalName", "username", "email")
        tap = _get_request_value(body, req, "tap", "temporaryAccessPass")
        display_name = _get_request_value(body, req, "displayName") or build_display_name()
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")
        user_agent = _resolve_user_agent(body, req)
        redirect_uri = _resolve_redirect_uri(body, req)

        credential = register_passkey_via_tap(
            config=config,
            user_principal_name=user_principal_name or "",
            tap=tap or "",
            display_name=display_name,
            key_vault_key_name=key_vault_key_name,
            user_agent=user_agent,
            redirect_uri=redirect_uri,
        )
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "tap",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
                "loginPropagation": _build_login_propagation_hint(),
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
        user_principal_name = _get_request_value(body, req, "userPrincipalName", "username", "email")
        ests_auth = _resolve_ests_auth_value(body, req)
        display_name = _get_request_value(body, req, "displayName", "passkeyDisplayName") or build_display_name()
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")
        user_agent = _resolve_user_agent(body, req)
        redirect_uri = _resolve_redirect_uri(body, req)

        credential = register_passkey_via_ests_auth(
            config=config,
            requested_user_principal_name=user_principal_name or "",
            ests_auth_cookie=ests_auth or "",
            display_name=display_name,
            key_vault_key_name=key_vault_key_name,
            user_agent=user_agent,
            redirect_uri=redirect_uri,
        )
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "estsauth",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
                "loginPropagation": _build_login_propagation_hint(),
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="QueuePasskeyRegistrationViaEstsAuth")
@app.route(route="passkeys/register/estsauth/queue", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
@app.queue_output(arg_name="registration_message", queue_name="%PASSKEY_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def queue_passkey_registration_via_ests_auth_http(
    req: func.HttpRequest,
    registration_message: func.Out[str],
) -> func.HttpResponse:
    try:
        body = _get_request_body(req)
        user_principal_name = _get_request_value(body, req, "userPrincipalName", "username", "email")
        if not user_principal_name:
            raise PasskeyValidationError("Missing required field 'userPrincipalName', 'username', or 'email'.")

        ests_auth = _resolve_ests_auth_value(body, req)
        if not ests_auth:
            raise PasskeyValidationError(
                "Missing required field 'estsAuth', 'estsAuthCookie', or a cookie export containing ESTSAUTH."
            )

        display_name = _get_request_value(body, req, "displayName", "passkeyDisplayName") or build_display_name()
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")
        user_agent = _resolve_user_agent(body, req)
        redirect_uri = _resolve_redirect_uri(body, req)
        queue_message = _build_registration_queue_message(
            user_principal_name=user_principal_name,
            ests_auth_cookie=ests_auth,
            display_name=display_name,
            key_vault_key_name=key_vault_key_name,
            user_agent=user_agent,
            redirect_uri=redirect_uri,
        )
        _write_registration_status(
            str(queue_message["requestId"]),
            {
                "requestId": queue_message["requestId"],
                "status": "queued",
                "authMethod": "estsauth",
                "queueName": os.getenv("PASSKEY_REGISTRATION_QUEUE_NAME", "passkey-registration"),
                "userPrincipalName": user_principal_name,
                "displayName": display_name,
                "keyVaultKeyName": key_vault_key_name,
                "queuedAtUtc": queue_message["queuedAtUtc"],
                "userAgent": user_agent,
                "redirectUri": redirect_uri,
            },
        )
        registration_message.set(json.dumps(queue_message, separators=(",", ":")))

        return _json_response(
            202,
            {
                "success": True,
                "queued": True,
                "authMethod": "estsauth",
                "requestId": queue_message["requestId"],
                "queueName": os.getenv("PASSKEY_REGISTRATION_QUEUE_NAME", "passkey-registration"),
                "userPrincipalName": user_principal_name,
                "statusUrl": _build_status_url(req, str(queue_message["requestId"])),
                "loginPropagation": _build_login_propagation_hint(),
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="ProcessPasskeyRegistrationViaEstsAuth")
@app.queue_trigger(arg_name="registration_message", queue_name="%PASSKEY_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def process_passkey_registration_via_ests_auth_queue(registration_message: func.QueueMessage) -> None:
    payload = json.loads(registration_message.get_body().decode("utf-8"))
    request_id = str(payload.get("requestId") or "")
    processing_started_at_utc = _utc_timestamp()
    _write_registration_status(
        request_id,
        {
            "requestId": request_id,
            "status": "processing",
            "authMethod": "estsauth",
            "queueName": os.getenv("PASSKEY_REGISTRATION_QUEUE_NAME", "passkey-registration"),
            "userPrincipalName": str(payload.get("userPrincipalName") or ""),
            "displayName": str(payload.get("displayName") or payload.get("passkeyDisplayName") or ""),
            "keyVaultKeyName": str(payload.get("keyVaultKeyName") or ""),
            "queuedAtUtc": str(payload.get("queuedAtUtc") or ""),
            "processingStartedAtUtc": processing_started_at_utc,
            "userAgent": normalize_user_agent(payload.get("userAgent") or payload.get("useragent")),
            "redirectUri": normalize_redirect_uri(payload.get("redirectUri") or payload.get("redirecturi")),
        },
    )
    try:
        result = _process_registration_queue_message(payload)
        credential = result["credential"]
        key_vault = credential.get("keyVault") if isinstance(credential, dict) else None
        key_name = key_vault.get("keyName") if isinstance(key_vault, dict) else None
        _write_registration_status(
            request_id,
            {
                "requestId": request_id,
                "status": "succeeded",
                "authMethod": "estsauth",
                "queueName": os.getenv("PASSKEY_REGISTRATION_QUEUE_NAME", "passkey-registration"),
                "userPrincipalName": result["userPrincipalName"],
                "keyVaultName": result["keyVaultName"],
                "keyVaultKeyName": str(payload.get("keyVaultKeyName") or ""),
                "displayName": str(payload.get("displayName") or payload.get("passkeyDisplayName") or ""),
                "queuedAtUtc": str(payload.get("queuedAtUtc") or ""),
                "processingStartedAtUtc": processing_started_at_utc,
                "completedAtUtc": _utc_timestamp(),
                "userAgent": normalize_user_agent(payload.get("userAgent") or payload.get("useragent")),
                "redirectUri": normalize_redirect_uri(payload.get("redirectUri") or payload.get("redirecturi")),
                "credential": credential,
            },
        )
        logging.info(
            "Processed ESTSAUTH passkey registration request %s for %s with key %s.",
            result["requestId"] or "<no-request-id>",
            result["userPrincipalName"],
            key_name or "<no-key-name>",
        )
    except Exception as exc:  # noqa: BLE001
        _write_registration_status(
            request_id,
            {
                "requestId": request_id,
                "status": "failed",
                "authMethod": "estsauth",
                "queueName": os.getenv("PASSKEY_REGISTRATION_QUEUE_NAME", "passkey-registration"),
                "userPrincipalName": str(payload.get("userPrincipalName") or ""),
                "keyVaultKeyName": str(payload.get("keyVaultKeyName") or ""),
                "displayName": str(payload.get("displayName") or payload.get("passkeyDisplayName") or ""),
                "queuedAtUtc": str(payload.get("queuedAtUtc") or ""),
                "processingStartedAtUtc": processing_started_at_utc,
                "failedAtUtc": _utc_timestamp(),
                "userAgent": normalize_user_agent(payload.get("userAgent") or payload.get("useragent")),
                "redirectUri": normalize_redirect_uri(payload.get("redirectUri") or payload.get("redirecturi")),
                "error": str(exc),
            },
        )
        raise


@app.function_name(name="GetPasskeyRegistrationStatus")
@app.route(route="passkeys/register/status/{requestId}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_passkey_registration_status_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        request_id = req.route_params.get("requestId") or req.params.get("requestId")
        if not request_id:
            raise PasskeyValidationError("Missing required route or query value 'requestId'.")

        status = _read_registration_status(request_id)
        if status is None:
            return _json_response(
                404,
                {
                    "success": False,
                    "requestId": request_id,
                    "error": "Registration request status was not found.",
                },
            )

        status["success"] = True
        return _json_response(200, status)
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
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
        user_agent = _resolve_user_agent(body, req)
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
            "user_agent": user_agent,
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
