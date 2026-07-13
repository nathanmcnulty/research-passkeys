from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
DEFAULT_CLIENT_ID = "okta.b8003760-1ca5-51b8-9404-85bb7ef9bc8c"
DEFAULT_SCOPE = (
    "openid profile email online_access okta.internal.enduser.read "
    "okta.myAccount.read okta.myAccount.manage okta.myAccount.profile.read "
    "okta.myAccount.profile.manage okta.enduser.dashboard.read okta.enduser.dashboard.manage"
)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def normalize_origin(domain: str) -> str:
    candidate = domain.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("OktaDomain must be an HTTPS host name only.")
    return f"https://{parsed.hostname}"


def same_org_url(href: str, origin: str) -> str:
    target = urlparse(href)
    base = urlparse(origin)
    if target.scheme != "https" or target.hostname != base.hostname:
        raise ValueError(f"Refusing cross-origin Okta remediation URL: {href}")
    return href


def remediation(response: dict[str, Any], name: str) -> dict[str, Any] | None:
    values = ((response.get("remediation") or {}).get("value") or [])
    return next((item for item in values if item.get("name") == name), None)


def webauthn_id(response: dict[str, Any]) -> str | None:
    candidates: list[dict[str, Any]] = []
    for key in ("authenticators", "authenticatorEnrollments", "currentAuthenticatorEnrollment"):
        value = (response.get(key) or {}).get("value")
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            candidates.append(value)
    for candidate in candidates:
        if candidate.get("key") == "webauthn" and candidate.get("id"):
            return str(candidate["id"])
    return None


def idx_post(session: requests.Session, href: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    response = session.post(
        href,
        headers=headers,
        json=body,
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f"IDX request failed for {href}: HTTP {response.status_code}: {response.text[:1000]}")
    return response.json()


def get_key_vault_token(configured: str | None = None) -> str:
    if configured:
        return configured
    env_token = os.getenv("PASSKEY_KEYVAULT_ACCESS_TOKEN") or os.getenv("AZURE_KEYVAULT_ACCESS_TOKEN")
    if env_token:
        return env_token
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://vault.azure.net", "--query", "accessToken", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    raise RuntimeError("Unable to acquire a Key Vault token. Use az login or --keyvault-access-token.")


def sign_digest(
    *,
    session: requests.Session,
    key_vault_name: str,
    key_name: str,
    digest: bytes,
    access_token: str,
    key_id: str | None = None,
) -> bytes:
    if key_id:
        parsed = urlparse(key_id)
        if parsed.scheme != "https" or parsed.hostname != f"{key_vault_name}.vault.azure.net" or len(parsed.path.strip("/").split("/")) != 3:
            raise ValueError("key_id must be a versioned HTTPS Key Vault key ID in the selected vault.")
        endpoint = f"{key_id.rstrip('/')}/sign?api-version=7.4"
    else:
        endpoint = f"https://{key_vault_name}.vault.azure.net/keys/{key_name}/sign?api-version=7.4"
    response = session.post(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"alg": "ES256", "value": b64url_encode(digest)},
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f"Key Vault signing failed: HTTP {response.status_code}: {response.text[:1000]}")
    raw = b64url_decode(response.json()["value"])
    if len(raw) != 64:
        raise ValueError(f"Expected a 64-byte ES256 Key Vault signature, got {len(raw)} bytes.")
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def create_key(
    *,
    session: requests.Session,
    key_vault_name: str,
    key_name: str,
    access_token: str,
) -> dict[str, Any]:
    response = session.post(
        f"https://{key_vault_name}.vault.azure.net/keys/{key_name}/create?api-version=7.4",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"kty": "EC", "crv": "P-256", "key_ops": ["sign", "verify"]},
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f"Key Vault key creation failed: HTTP {response.status_code}: {response.text[:1000]}")
    key = (response.json().get("key") or {})
    if not all(key.get(name) for name in ("kid", "x", "y")):
        raise RuntimeError("Key Vault did not return EC key coordinates.")
    return key


def load_record(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def credential_values(
    record: dict[str, Any] | None,
    *,
    credential_id: str | None,
    key_vault_name: str | None,
    key_name: str | None,
    key_id: str | None,
    relying_party: str | None,
) -> tuple[str, str, str, str | None, str]:
    record = record or {}
    vault = record.get("keyVault") or {}
    resolved = (
        credential_id or record.get("credentialId"),
        key_vault_name or vault.get("vaultName"),
        key_name or vault.get("keyName"),
        key_id or vault.get("keyId"),
        relying_party or record.get("relyingParty"),
    )
    if not all(resolved[:3]):
        raise ValueError("Provide credential_id, key_vault_name, and key_name, or use --credential-path.")
    return str(resolved[0]), str(resolved[1]), str(resolved[2]), resolved[3], str(resolved[4] or "")


def build_assertion(*, challenge: str, origin: str, relying_party: str, sign_count: int, key_values: tuple[str, str, str, str | None, str], session: requests.Session, access_token: str) -> tuple[dict[str, str], str]:
    credential_id, key_vault_name, key_name, key_id, _ = key_values
    rp_hash = hashlib.sha256(relying_party.encode("utf-8")).digest()
    auth_data = rp_hash + bytes([0x05]) + sign_count.to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    signature = sign_digest(
        session=session,
        key_vault_name=key_vault_name,
        key_name=key_name,
        key_id=key_id,
        digest=digest,
        access_token=access_token,
    )
    return {
        "clientData": base64.b64encode(client_data).decode("ascii"),
        "authenticatorData": base64.b64encode(auth_data).decode("ascii"),
        "signatureData": base64.b64encode(signature).decode("ascii"),
    }, credential_id
