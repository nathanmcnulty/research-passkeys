from __future__ import annotations

import subprocess

import requests
from azure.identity import ManagedIdentityCredential

from .common import KeyVaultKeyMaterial, PasskeyProtocolError, PasskeyValidationError, b64url_decode


def get_key_vault_access_token(
    *,
    configured_token: str | None,
    managed_identity_client_id: str | None,
    azure_cli_tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    tenant_id: str | None = None,
) -> str:
    if configured_token:
        return configured_token

    if managed_identity_client_id is not None or _is_running_in_azure():
        credential = ManagedIdentityCredential(client_id=managed_identity_client_id or None)
        try:
            return credential.get_token("https://vault.azure.net/.default").token
        except Exception:  # noqa: BLE001
            pass

    cli_command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        "https://vault.azure.net",
        "--query",
        "accessToken",
        "-o",
        "tsv",
    ]
    if azure_cli_tenant_id:
        cli_command.extend(["--tenant", azure_cli_tenant_id])

    try:
        result = subprocess.run(
            cli_command,
            capture_output=True,
            text=True,
            check=True,
        )
        token = result.stdout.strip()
        if token:
            return token
    except Exception:  # noqa: BLE001
        pass

    if client_id and client_secret and tenant_id:
        response = requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
                "scope": "https://vault.azure.net/.default",
            },
            timeout=60,
        )
        if response.ok:
            token = response.json().get("access_token")
            if token:
                return token
        raise PasskeyProtocolError(
            f"Failed to acquire a Key Vault access token via service principal: HTTP {response.status_code}. "
            f"ResponseBody={response.text[:1000]}"
        )

    raise PasskeyProtocolError(
        "Unable to acquire a Key Vault access token. Set PASSKEY_KEYVAULT_ACCESS_TOKEN, "
        "sign in with Azure CLI, provide service principal credentials, or run in Azure with managed identity."
    )


def _is_running_in_azure() -> bool:
    import os

    return bool(os.getenv("IDENTITY_ENDPOINT") or os.getenv("MSI_ENDPOINT"))


def create_ec_key(
    *,
    session: requests.Session,
    key_vault_name: str,
    key_name: str,
    access_token: str,
) -> KeyVaultKeyMaterial:
    uri = f"https://{key_vault_name}.vault.azure.net/keys/{key_name}/create?api-version=7.4"
    response = session.post(
        uri,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json={
            "kty": "EC",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
        },
        timeout=60,
    )

    if not response.ok:
        snippet = response.text[:1000] if response.text else "(empty)"
        raise PasskeyProtocolError(
            f"Failed to create key in Key Vault '{key_vault_name}': HTTP {response.status_code}. "
            f"ResponseBody={snippet}"
        )

    payload = response.json()
    key = payload.get("key") or {}
    try:
        key_id = key["kid"]
        public_key_x = b64url_decode(key["x"])
        public_key_y = b64url_decode(key["y"])
    except KeyError as exc:
        raise PasskeyValidationError("Key Vault did not return the expected EC key coordinates.") from exc

    return KeyVaultKeyMaterial(
        key_name=key_name,
        key_id=key_id,
        public_key_x=public_key_x,
        public_key_y=public_key_y,
    )
