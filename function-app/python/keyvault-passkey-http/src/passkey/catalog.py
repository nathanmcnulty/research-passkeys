from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .common import PasskeyValidationError


def build_catalog_record(provider: str, credential: dict[str, Any]) -> dict[str, Any]:
    """Convert a provider login credential into the transport-neutral catalog v1 record."""
    if provider not in {"entra", "okta"}:
        raise PasskeyValidationError("provider must be 'entra' or 'okta'.")
    key_vault = credential.get("keyVault")
    if not isinstance(key_vault, dict):
        raise PasskeyValidationError("Credential is missing Key Vault coordinates.")
    credential_id = str(credential.get("credentialId") or "").strip()
    rp_id = str(credential.get("relyingParty") or credential.get("rpId") or "").strip()
    user_name = str(credential.get("userName") or credential.get("username") or "").strip()
    vault_name = str(key_vault.get("vaultName") or "").strip()
    key_name = str(key_vault.get("keyName") or "").strip()
    key_id = str(key_vault.get("keyId") or "").strip()
    if not all((credential_id, rp_id, user_name, vault_name, key_name, key_id)):
        raise PasskeyValidationError(
            "Credential cataloging requires credentialId, relyingParty, userName, and complete Key Vault coordinates."
        )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    created_at = str(credential.get("createdDateTime") or credential.get("createdAt") or now)
    record_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"passkey:{provider}:{vault_name.lower()}:{credential_id}"))
    provider_metadata = credential.get(provider)
    return {
        "schemaVersion": "1",
        "recordId": record_id,
        "provider": provider,
        "credentialId": credential_id,
        "rpId": rp_id,
        "userHandle": str(credential.get("userHandle") or "") or None,
        "userName": user_name,
        "displayName": str(credential.get("displayName") or user_name),
        "origin": str(credential.get("url") or "") or None,
        "keyVault": {"vaultName": vault_name, "keyName": key_name, "keyId": key_id},
        "status": "active",
        "signCount": int(credential.get("signCount") or credential.get("counter") or 0),
        "createdAt": created_at,
        "updatedAt": now,
        "providerMetadata": dict(provider_metadata) if isinstance(provider_metadata, dict) else {},
    }
