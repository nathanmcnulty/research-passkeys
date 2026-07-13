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
    login_okta_idx_session,
    login_okta_passkey,
    register_okta_idx_session,
    register_passkey_via_ests_auth,
    register_passkey_via_tap,
    start_myaccount_registration,
)
from passkey.okta import PasskeySecurityError as OktaPasskeySecurityError

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


def _resolve_okta_domain(body: dict[str, object], req: func.HttpRequest) -> str:
    domain = _get_request_value(body, req, "oktaDomain", "domain") or os.getenv("PASSKEY_OKTA_DOMAIN", "").strip()
    if not domain:
        raise PasskeyValidationError("Missing required Okta domain. Set PASSKEY_OKTA_DOMAIN or provide 'oktaDomain'.")
    return domain


def _resolve_okta_access_token(body: dict[str, object], req: func.HttpRequest) -> str:
    token = _get_request_value(body, req, "accessToken", "oktaAccessToken")
    if not token:
        authorization = req.headers.get("Authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        raise PasskeyValidationError("Missing Okta user access token. Provide 'accessToken' or a Bearer Authorization header.")
    return token


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


def _build_status_url(req: func.HttpRequest, request_id: str, provider: str = "entra") -> str:
    base_url = req.url.split("?", 1)[0].rstrip("/")
    queue_suffixes = (
        f"/api/{provider}/passkeys/register/estsauth/queue",
        f"/api/{provider}/passkeys/register/idx/queue",
    )
    queue_suffix = next((suffix for suffix in queue_suffixes if base_url.endswith(suffix)), None)
    if queue_suffix:
        status_url = f"{base_url[: -len(queue_suffix)]}/api/{provider}/passkeys/register/status/{request_id}"
    else:
        status_url = f"/api/{provider}/passkeys/register/status/{request_id}"
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


def _build_okta_queue_message(*, body: dict[str, object], req: func.HttpRequest) -> dict[str, object]:
    cookie_header = _get_request_value(body, req, "cookieHeader", "cookie")
    state_handle = _get_request_value(body, req, "stateHandle")
    authenticator_id = _get_request_value(body, req, "authenticatorId")
    if not cookie_header or not state_handle or not authenticator_id:
        raise PasskeyValidationError("Okta queue requests require cookieHeader, stateHandle, and authenticatorId.")
    transport = _get_request_value(body, req, "transport") or "usb"
    if transport not in {"usb", "internal"}:
        raise PasskeyValidationError("transport must be 'usb' or 'internal'.")
    return {
        "requestId": str(uuid.uuid4()),
        "queuedAtUtc": _utc_timestamp(),
        "provider": "okta",
        "authMethod": "idx",
        "oktaDomain": _resolve_okta_domain(body, req),
        "cookieHeader": cookie_header,
        "stateHandle": state_handle,
        "authenticatorId": authenticator_id,
        "keyVaultKeyName": _get_request_value(body, req, "keyVaultKeyName"),
        "transport": transport,
    }


def _process_okta_queue_message(message_payload: dict[str, object]) -> dict[str, object]:
    config = load_config_from_environment()
    credential = register_okta_idx_session(
        config=config,
        okta_domain=str(message_payload.get("oktaDomain") or ""),
        cookie_header=str(message_payload.get("cookieHeader") or ""),
        state_handle=str(message_payload.get("stateHandle") or ""),
        authenticator_id=str(message_payload.get("authenticatorId") or ""),
        key_vault_key_name=str(message_payload.get("keyVaultKeyName") or "") or None,
        transport=str(message_payload.get("transport") or "usb"),
    )
    return {"requestId": str(message_payload.get("requestId") or ""), "credential": credential}


def _get_credential_payload(body: dict[str, object]) -> dict[str, object]:
    credential = body.get("credential")
    if isinstance(credential, dict):
        return dict(credential)

    return {
        key: value
        for key, value in body.items()
        if key not in {
            "credential", "authUrl", "keyVaultName", "keyVaultKeyName", "keyVaultAccessToken",
            "userAgent", "useragent", "redirectUri", "redirecturi", "oktaDomain", "domain",
            "accessToken", "oktaAccessToken", "cookieHeader", "cookie", "stateHandle",
            "authenticatorId", "challenge", "transport", "password", "clientId", "signCount",
        }
    }


def _apply_key_vault_overrides(body: dict[str, object], req: func.HttpRequest, credential: dict[str, object]) -> dict[str, object]:
    vault_name = _get_request_value(body, req, "keyVaultName")
    key_name = _get_request_value(body, req, "keyVaultKeyName")
    key_id = _get_request_value(body, req, "keyVaultKeyId")
    if not any((vault_name, key_name, key_id)):
        return credential
    key_vault = dict(credential.get("keyVault")) if isinstance(credential.get("keyVault"), dict) else {}
    if vault_name:
        key_vault["vaultName"] = vault_name
    if key_name:
        key_vault["keyName"] = key_name
    if key_id:
        key_vault["keyId"] = key_id
    credential["keyVault"] = key_vault
    return credential


@app.function_name(name="RegisterEntraPasskeyViaTap")
@app.route(route="entra/passkeys/register/tap", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_entra_passkey_via_tap_http(req: func.HttpRequest) -> func.HttpResponse:
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


@app.function_name(name="RegisterEntraPasskeyViaEstsAuth")
@app.route(route="entra/passkeys/register/estsauth", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_entra_passkey_via_ests_auth_http(req: func.HttpRequest) -> func.HttpResponse:
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


@app.function_name(name="QueueEntraPasskeyRegistrationViaEstsAuth")
@app.route(route="entra/passkeys/register/estsauth/queue", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
@app.queue_output(arg_name="registration_message", queue_name="%PASSKEY_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def queue_entra_passkey_registration_via_ests_auth_http(
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


@app.function_name(name="ProcessEntraPasskeyRegistrationViaEstsAuth")
@app.queue_trigger(arg_name="registration_message", queue_name="%PASSKEY_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def process_entra_passkey_registration_via_ests_auth_queue(registration_message: func.QueueMessage) -> None:
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


@app.function_name(name="GetEntraPasskeyRegistrationStatus")
@app.route(route="entra/passkeys/register/status/{requestId}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_entra_passkey_registration_status_http(req: func.HttpRequest) -> func.HttpResponse:
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


@app.function_name(name="LoginWithEntraPasskey")
@app.route(route="entra/passkeys/login", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def login_with_entra_passkey_http(req: func.HttpRequest) -> func.HttpResponse:
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


@app.function_name(name="StartOktaMyAccountWebAuthnRegistration")
@app.route(route="okta/passkeys/register/myaccount", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def start_okta_myaccount_webauthn_registration_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = _get_request_body(req)
        result = start_myaccount_registration(
            okta_domain=_resolve_okta_domain(body, req),
            access_token=_resolve_okta_access_token(body, req),
        )
        return _json_response(200, {"success": True, "provider": "okta", "registration": result})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="RegisterOktaPasskeyViaIdxSession")
@app.route(route="okta/passkeys/register/idx", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def register_okta_passkey_via_idx_session_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        credential = register_okta_idx_session(
            config=config,
            okta_domain=_resolve_okta_domain(body, req),
            cookie_header=_get_request_value(body, req, "cookieHeader", "cookie") or "",
            state_handle=_get_request_value(body, req, "stateHandle") or "",
            authenticator_id=_get_request_value(body, req, "authenticatorId") or "",
            key_vault_name=_get_request_value(body, req, "keyVaultName"),
            key_vault_key_name=_get_request_value(body, req, "keyVaultKeyName"),
            key_vault_access_token=_get_request_value(body, req, "keyVaultAccessToken"),
            transport=_get_request_value(body, req, "transport") or "usb",
        )
        return _json_response(200, {"success": True, "provider": "okta", "authMethod": "idx", "credential": credential})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except OktaPasskeySecurityError as exc:
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="QueueOktaPasskeyRegistrationViaIdxSession")
@app.route(route="okta/passkeys/register/idx/queue", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
@app.queue_output(arg_name="registration_message", queue_name="%PASSKEY_OKTA_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def queue_okta_passkey_registration_via_idx_session_http(
    req: func.HttpRequest,
    registration_message: func.Out[str],
) -> func.HttpResponse:
    try:
        body = _get_request_body(req)
        queue_message = _build_okta_queue_message(body=body, req=req)
        _write_registration_status(
            str(queue_message["requestId"]),
            {
                "requestId": queue_message["requestId"],
                "provider": "okta",
                "authMethod": "idx",
                "status": "queued",
                "queueName": os.getenv("PASSKEY_OKTA_REGISTRATION_QUEUE_NAME", "okta-passkey-registration"),
                "queuedAtUtc": queue_message["queuedAtUtc"],
                "oktaDomain": queue_message["oktaDomain"],
                "warning": "Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.",
            },
        )
        registration_message.set(json.dumps(queue_message, separators=(",", ":")))
        return _json_response(
            202,
            {
                "success": True,
                "queued": True,
                "provider": "okta",
                "authMethod": "idx",
                "requestId": queue_message["requestId"],
                "queueName": os.getenv("PASSKEY_OKTA_REGISTRATION_QUEUE_NAME", "okta-passkey-registration"),
                "statusUrl": _build_status_url(req, str(queue_message["requestId"]), provider="okta"),
                "warning": "Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.",
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="ProcessOktaPasskeyRegistrationViaIdxSession")
@app.queue_trigger(arg_name="registration_message", queue_name="%PASSKEY_OKTA_REGISTRATION_QUEUE_NAME%", connection="AzureWebJobsStorage")
def process_okta_passkey_registration_via_idx_session_queue(registration_message: func.QueueMessage) -> None:
    payload = json.loads(registration_message.get_body().decode("utf-8"))
    request_id = str(payload.get("requestId") or "")
    _write_registration_status(
        request_id,
        {
            "requestId": request_id,
            "provider": "okta",
            "authMethod": "idx",
            "status": "processing",
            "queueName": os.getenv("PASSKEY_OKTA_REGISTRATION_QUEUE_NAME", "okta-passkey-registration"),
            "oktaDomain": str(payload.get("oktaDomain") or ""),
            "warning": "Okta IDX stateHandle and browser cookies are short-lived. Queue processing should begin immediately.",
        },
    )
    try:
        result = _process_okta_queue_message(payload)
        _write_registration_status(
            request_id,
            {
                "requestId": request_id,
                "provider": "okta",
                "authMethod": "idx",
                "status": "succeeded",
                "queueName": os.getenv("PASSKEY_OKTA_REGISTRATION_QUEUE_NAME", "okta-passkey-registration"),
                "oktaDomain": str(payload.get("oktaDomain") or ""),
                "completedAtUtc": _utc_timestamp(),
                "credential": result["credential"],
            },
        )
    except Exception as exc:  # noqa: BLE001
        _write_registration_status(
            request_id,
            {
                "requestId": request_id,
                "provider": "okta",
                "authMethod": "idx",
                "status": "failed",
                "queueName": os.getenv("PASSKEY_OKTA_REGISTRATION_QUEUE_NAME", "okta-passkey-registration"),
                "oktaDomain": str(payload.get("oktaDomain") or ""),
                "failedAtUtc": _utc_timestamp(),
                "error": str(exc),
            },
        )
        raise


@app.function_name(name="GetOktaPasskeyRegistrationStatus")
@app.route(route="okta/passkeys/register/status/{requestId}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_okta_passkey_registration_status_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        request_id = req.route_params.get("requestId") or req.params.get("requestId")
        if not request_id:
            raise PasskeyValidationError("Missing required route or query value 'requestId'.")
        status = _read_registration_status(request_id)
        if status is None:
            return _json_response(404, {"success": False, "provider": "okta", "requestId": request_id, "error": "Registration request status was not found."})
        status["success"] = True
        status["provider"] = "okta"
        return _json_response(200, status)
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="LoginWithOktaPasskey")
@app.route(route="okta/passkeys/login", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def login_with_okta_passkey_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        credential = _apply_key_vault_overrides(body, req, _get_credential_payload(body))
        user_name = _get_request_value(body, req, "userName", "username", "email") or str(credential.get("userName") or credential.get("username") or "")
        key_vault_access_token = _get_request_value(body, req, "keyVaultAccessToken")
        result = login_okta_passkey(
            config=config,
            okta_domain=_resolve_okta_domain(body, req),
            user_name=user_name,
            credential=credential,
            key_vault_access_token=key_vault_access_token,
            password=_get_request_value(body, req, "password"),
            client_id=_get_request_value(body, req, "clientId") or "okta.b8003760-1ca5-51b8-9404-85bb7ef9bc8c",
            redirect_uri=_get_request_value(body, req, "redirectUri"),
            sign_count=int(_get_request_value(body, req, "signCount") or "1"),
        )
        return _json_response(200, {"provider": "okta", "authMethod": "idx", **result})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except OktaPasskeySecurityError as exc:
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="TestOktaPasskeyLoginViaIdxSession")
@app.route(route="okta/passkeys/login/idx", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def test_okta_passkey_login_via_idx_session_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        config = load_config_from_environment()
        body = _get_request_body(req)
        credential = _apply_key_vault_overrides(body, req, _get_credential_payload(body))
        result = login_okta_idx_session(
            config=config,
            okta_domain=_resolve_okta_domain(body, req),
            cookie_header=_get_request_value(body, req, "cookieHeader", "cookie") or "",
            state_handle=_get_request_value(body, req, "stateHandle") or "",
            challenge=_get_request_value(body, req, "challenge") or "",
            credential=credential,
            key_vault_access_token=_get_request_value(body, req, "keyVaultAccessToken"),
            sign_count=int(_get_request_value(body, req, "signCount") or "0"),
        )
        return _json_response(200, {"provider": "okta", "authMethod": "idx", **result})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except OktaPasskeySecurityError as exc:
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})
