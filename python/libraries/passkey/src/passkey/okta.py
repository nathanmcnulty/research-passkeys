from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from .common import PasskeyProtocolError, PasskeyValidationError, b64url_decode, b64url_encode, normalize_user_agent
from .keyvault import create_ec_key, get_key_vault_access_token


DEFAULT_OKTA_CLIENT_ID = "okta.b8003760-1ca5-51b8-9404-85bb7ef9bc8c"
OKTA_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
OKTA_SCOPE = (
    "openid profile email online_access okta.internal.enduser.read "
    "okta.myAccount.read okta.myAccount.manage okta.myAccount.profile.read "
    "okta.myAccount.profile.manage okta.enduser.dashboard.read okta.enduser.dashboard.manage"
)


def normalize_okta_origin(domain: str) -> str:
    candidate = domain.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
        raise PasskeyValidationError("Okta domain must be an HTTPS host name only.")
    return f"https://{parsed.hostname}"


def _same_org_url(href: str, origin: str) -> str:
    target = urlparse(href)
    base = urlparse(origin)
    if target.scheme != "https" or target.hostname != base.hostname:
        raise PasskeySecurityError(f"Refusing cross-origin Okta remediation URL: {href}")
    return href


class PasskeySecurityError(PasskeyProtocolError):
    pass


def _idx_headers(
    origin: str,
    *,
    accept: str = "application/ion+json; okta-version=1.0.0",
    user_agent: str = OKTA_USER_AGENT,
) -> dict[str, str]:
    return {"Accept": accept, "Origin": origin, "Referer": f"{origin}/", "User-Agent": user_agent}


def _idx_post(session: requests.Session, href: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    response = session.post(href, headers=headers, json=body, timeout=60)
    if not response.ok:
        raise PasskeyProtocolError(f"Okta IDX request failed: HTTP {response.status_code}: {response.text[:1000]}")
    try:
        return response.json()
    except ValueError as exc:
        raise PasskeyProtocolError("Okta returned a non-JSON IDX response.") from exc


def _remediation(response: dict[str, Any], name: str) -> dict[str, Any] | None:
    values = ((response.get("remediation") or {}).get("value") or [])
    return next((value for value in values if value.get("name") == name), None)


def _webauthn_id(response: dict[str, Any]) -> str | None:
    candidates: list[dict[str, Any]] = []
    for name in ("authenticators", "authenticatorEnrollments", "currentAuthenticatorEnrollment"):
        value = (response.get(name) or {}).get("value")
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            candidates.append(value)
    for candidate in candidates:
        if candidate.get("key") == "webauthn" and candidate.get("id"):
            return str(candidate["id"])
    return None


def start_myaccount_registration(*, okta_domain: str, access_token: str) -> dict[str, Any]:
    if not access_token.strip():
        raise PasskeyValidationError("Missing required Okta user access token.")
    origin = normalize_okta_origin(okta_domain)
    response = requests.post(
        f"{origin}/idp/myaccount/webauthn/registration",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json; okta-version=1.0.0",
            "Content-Type": "application/json",
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(f"Okta registration-start failed: HTTP {response.status_code}: {response.text[:1000]}")
    payload = response.json()
    options = payload.get("options") or {}
    if not options.get("challenge") or not payload.get("expiresAt"):
        raise PasskeyProtocolError("Okta returned an unexpected MyAccount registration response.")
    return {"success": True, "origin": origin, **payload}


def _key_vault_token(config: Any, configured_token: str | None = None) -> str:
    return get_key_vault_access_token(
        configured_token=configured_token or getattr(config, "key_vault_access_token", None),
        managed_identity_client_id=getattr(config, "managed_identity_client_id", None),
        azure_cli_tenant_id=getattr(config, "tenant_id", None),
    )


def _sign_digest(*, session: requests.Session, key_vault_name: str, key_name: str, key_id: str | None, digest: bytes, token: str) -> bytes:
    if key_id:
        parsed = urlparse(key_id)
        if parsed.scheme != "https" or parsed.hostname != f"{key_vault_name}.vault.azure.net" or len(parsed.path.strip("/").split("/")) != 3:
            raise PasskeyValidationError("Key Vault key ID must be a versioned key in the selected vault.")
        endpoint = f"{key_id.rstrip('/')}/sign?api-version=7.4"
    else:
        endpoint = f"https://{key_vault_name}.vault.azure.net/keys/{key_name}/sign?api-version=7.4"
    response = session.post(
        endpoint,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"alg": "ES256", "value": b64url_encode(digest)},
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(f"Key Vault signing failed: HTTP {response.status_code}: {response.text[:1000]}")
    raw = b64url_decode(response.json()["value"])
    if len(raw) != 64:
        raise PasskeyProtocolError(f"Expected a 64-byte ES256 signature, got {len(raw)} bytes.")
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def _assertion(*, session: requests.Session, origin: str, relying_party: str, challenge: str, sign_count: int, key_vault_name: str, key_name: str, key_id: str | None, token: str) -> dict[str, str]:
    if sign_count < 0 or sign_count > 2**32 - 1:
        raise PasskeyValidationError("signCount must be between 0 and 4294967295.")
    auth_data = hashlib.sha256(relying_party.encode("utf-8")).digest() + bytes([0x05]) + sign_count.to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    signature = _sign_digest(
        session=session,
        key_vault_name=key_vault_name,
        key_name=key_name,
        key_id=key_id,
        digest=digest,
        token=token,
    )
    return {
        "clientData": base64.b64encode(client_data).decode("ascii"),
        "authenticatorData": base64.b64encode(auth_data).decode("ascii"),
        "signatureData": base64.b64encode(signature).decode("ascii"),
    }


def _import_cookie_header(session: requests.Session, cookie_header: str, origin: str) -> int:
    count = 0
    host = urlparse(origin).hostname
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        name, value = item.strip().split("=", 1)
        if name:
            session.cookies.set(name, value, domain=host, path="/")
            count += 1
    if count == 0:
        raise PasskeyValidationError("Cookie header did not contain importable cookies.")
    return count


def register_okta_idx_session(
    *,
    config: Any,
    okta_domain: str,
    cookie_header: str,
    state_handle: str,
    authenticator_id: str,
    key_vault_name: str | None = None,
    key_vault_key_name: str | None = None,
    key_vault_access_token: str | None = None,
    transport: str = "usb",
) -> dict[str, Any]:
    if transport not in {"usb", "internal"}:
        raise PasskeyValidationError("transport must be 'usb' or 'internal'.")
    origin = normalize_okta_origin(okta_domain)
    host = urlparse(origin).hostname or ""
    session = requests.Session()
    _import_cookie_header(session, cookie_header, origin)
    headers = _idx_headers(origin, accept="application/json")
    selected = _idx_post(
        session,
        f"{origin}/idp/idx/credential/enroll",
        {"authenticator": {"id": authenticator_id}, "stateHandle": state_handle},
        headers,
    )
    activation = (((selected.get("currentAuthenticator") or {}).get("value") or {}).get("contextualData") or {}).get("activationData") or {}
    if not activation.get("challenge") or not activation.get("user") or not activation.get("pubKeyCredParams"):
        raise PasskeyProtocolError("Okta did not return WebAuthn activation data.")
    if -7 not in [item.get("alg") for item in activation["pubKeyCredParams"]]:
        raise PasskeyProtocolError("Okta did not offer ES256 (-7) for this enrollment.")
    finish = _remediation(selected, "enroll-authenticator")
    if not finish:
        raise PasskeyProtocolError("Okta did not return the enroll-authenticator remediation.")
    vault_name = key_vault_name or getattr(config, "key_vault_name", None)
    if not vault_name:
        raise PasskeyValidationError("Key Vault name is required.")
    user_name = str((activation.get("user") or {}).get("name") or "user")
    safe_user = "".join(character for character in user_name if character.isalnum() or character == "-").lower()[:12] or "oktauser"
    key_name = key_vault_key_name or f"okta-pk-{safe_user}-{secrets.randbelow(900000) + 100000}"
    key = create_ec_key(
        session=session,
        key_vault_name=vault_name,
        key_name=key_name,
        access_token=_key_vault_token(config, key_vault_access_token),
    )
    credential_id_bytes = secrets.token_bytes(32)
    credential_id = b64url_encode(credential_id_bytes)
    cose_key = {1: 2, 3: -7, -1: 1, -2: key.public_key_x, -3: key.public_key_y}
    rp_id = str((activation.get("rp") or {}).get("id") or host)
    auth_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([0x45])
        + bytes(4)
        + bytes(16)
        + len(credential_id_bytes).to_bytes(2, "big")
        + credential_id_bytes
        + cbor2.dumps(cose_key)
    )
    client_data = json.dumps(
        {"type": "webauthn.create", "challenge": activation["challenge"], "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    batch_key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Key Vault Passkey POC")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Key Vault Passkey POC")]))
        .public_key(batch_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(batch_key, hashes.SHA256())
    )
    attestation_signature = batch_key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    attestation = cbor2.dumps({"fmt": "packed", "attStmt": {"alg": -7, "sig": attestation_signature, "x5c": [certificate.public_bytes(serialization.Encoding.DER)]}, "authData": auth_data})
    completion = _idx_post(
        session,
        _same_org_url(finish["href"], origin),
        {"credentials": {"clientData": base64.b64encode(client_data).decode(), "attestation": base64.b64encode(attestation).decode(), "transports": json.dumps([transport], separators=(",", ":")), "clientExtensions": json.dumps({"credProps": {"rk": False}}, separators=(",", ":"))}, "stateHandle": selected.get("stateHandle")},
        headers,
    )
    if not completion.get("success"):
        raise PasskeyProtocolError("Okta did not return a success remediation for registration.")
    return {
        "credentialId": credential_id,
        "relyingParty": rp_id,
        "url": origin,
        "userName": user_name,
        "keyVault": {"vaultName": vault_name, "keyName": key_name, "keyId": key.key_id},
        "okta": {"userId": str((activation.get("user") or {}).get("id") or ""), "transport": transport},
    }


def login_okta_passkey(
    *,
    config: Any,
    okta_domain: str,
    user_name: str,
    credential: dict[str, Any],
    key_vault_access_token: str | None = None,
    password: str | None = None,
    client_id: str = DEFAULT_OKTA_CLIENT_ID,
    redirect_uri: str | None = None,
    sign_count: int = 1,
    user_agent: str = OKTA_USER_AGENT,
) -> dict[str, Any]:
    origin = normalize_okta_origin(okta_domain)
    host = urlparse(origin).hostname or ""
    key_vault = credential.get("keyVault") if isinstance(credential.get("keyVault"), dict) else {}
    credential_id = str(credential.get("credentialId") or "")
    key_vault_name = str(key_vault.get("vaultName") or getattr(config, "key_vault_name", ""))
    key_name = str(key_vault.get("keyName") or "")
    key_id = str(key_vault.get("keyId") or "") or None
    if not user_name or not credential_id or not key_vault_name or not key_name:
        raise PasskeyValidationError("Okta login requires userName, credentialId, and Key Vault coordinates.")
    relying_party = str(credential.get("relyingParty") or credential.get("rpId") or host)
    redirect_uri = redirect_uri or f"{origin}/account-settings/callback"
    verifier = b64url_encode(secrets.token_bytes(32))
    oauth_state = b64url_encode(secrets.token_bytes(24))
    authorize_uri = f"{origin}/oauth2/v1/authorize?{urlencode({'client_id': client_id, 'redirect_uri': redirect_uri, 'response_type': 'code', 'response_mode': 'query', 'scope': OKTA_SCOPE, 'state': oauth_state, 'nonce': b64url_encode(secrets.token_bytes(24)), 'code_challenge': b64url_encode(hashlib.sha256(verifier.encode('ascii')).digest()), 'code_challenge_method': 'S256'})}"
    session = requests.Session()
    page = session.get(authorize_uri, headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": user_agent}, timeout=60)
    if not page.ok:
        raise PasskeyProtocolError(f"Okta authorization page failed: HTTP {page.status_code}")
    match = re.search(r"var\s+stateToken\s*=\s*'([^']+)'", page.text)
    if not match:
        raise PasskeyProtocolError("Could not extract Okta stateToken from the authorization page.")
    state_token = re.sub(r"\\x([0-9a-fA-F]{2})", lambda value: chr(int(value.group(1), 16)), match.group(1))
    headers = _idx_headers(origin, user_agent=user_agent)
    introspect = _idx_post(session, f"{origin}/idp/idx/introspect", {"stateToken": state_token}, headers)
    identify = _remediation(introspect, "identify")
    if not identify:
        raise PasskeyProtocolError("Okta did not return the identify remediation.")
    identified = _idx_post(session, _same_org_url(identify["href"], origin), {"identifier": user_name, "stateHandle": introspect.get("stateHandle")}, headers)
    authenticator_id = _webauthn_id(identified)
    if not authenticator_id:
        raise PasskeyProtocolError("Okta did not report an enrolled WebAuthn authenticator.")
    current = identified
    if password:
        password_remediation = _remediation(current, "challenge-authenticator")
        if password_remediation:
            current = _idx_post(session, _same_org_url(password_remediation["href"], origin), {"credentials": {"passcode": password}, "stateHandle": current.get("stateHandle")}, headers)
            authenticator_id = _webauthn_id(current) or authenticator_id
    select = _remediation(current, "select-authenticator-authenticate")
    if not select:
        raise PasskeyProtocolError("Okta did not offer authenticator selection; the policy may require a password.")
    selected = _idx_post(session, _same_org_url(select["href"], origin), {"authenticator": {"id": authenticator_id}, "stateHandle": current.get("stateHandle")}, headers)
    challenge = (((selected.get("currentAuthenticator") or {}).get("value") or {}).get("contextualData") or {}).get("challengeData", {}).get("challenge")
    if not challenge:
        raise PasskeyProtocolError("Okta did not return a WebAuthn challenge.")
    assertion = _assertion(session=session, origin=origin, relying_party=relying_party, challenge=str(challenge), sign_count=sign_count, key_vault_name=key_vault_name, key_name=key_name, key_id=key_id, token=_key_vault_token(config, key_vault_access_token))
    answer = _remediation(selected, "challenge-authenticator")
    if not answer:
        raise PasskeyProtocolError("Okta did not return the WebAuthn challenge-answer remediation.")
    success = _idx_post(session, _same_org_url(answer["href"], origin), {"credentials": assertion, "stateHandle": selected.get("stateHandle")}, headers)
    if not success.get("success"):
        messages = "; ".join(str(item.get("message")) for item in ((success.get("messages") or {}).get("value") or []))
        raise PasskeyProtocolError(messages or "Okta rejected the passkey assertion.")
    first_hop = session.get(_same_org_url(success["success"]["href"], origin), allow_redirects=False, timeout=60)
    return {"success": True, "userName": user_name, "credentialId": credential_id, "successRedirected": bool(first_hop.headers.get("Location")), "redirectStatus": first_hop.status_code}


def login_okta_idx_session(
    *,
    config: Any,
    okta_domain: str,
    cookie_header: str,
    state_handle: str,
    challenge: str,
    credential: dict[str, Any],
    key_vault_access_token: str | None = None,
    sign_count: int = 0,
) -> dict[str, Any]:
    origin = normalize_okta_origin(okta_domain)
    host = urlparse(origin).hostname or ""
    session = requests.Session()
    _import_cookie_header(session, cookie_header, origin)
    key_vault = credential.get("keyVault") if isinstance(credential.get("keyVault"), dict) else {}
    key_vault_name = str(key_vault.get("vaultName") or getattr(config, "key_vault_name", ""))
    key_name = str(key_vault.get("keyName") or "")
    key_id = str(key_vault.get("keyId") or "") or None
    if not credential.get("credentialId") or not key_vault_name or not key_name:
        raise PasskeyValidationError("Okta IDX login requires credentialId and Key Vault coordinates.")
    assertion = _assertion(session=session, origin=origin, relying_party=str(credential.get("relyingParty") or host), challenge=challenge, sign_count=sign_count, key_vault_name=key_vault_name, key_name=key_name, key_id=key_id, token=_key_vault_token(config, key_vault_access_token))
    response = session.post(f"{origin}/idp/idx/challenge/answer", headers=_idx_headers(origin, accept="application/json"), json={"credentials": assertion, "stateHandle": state_handle}, timeout=60)
    if not response.ok:
        raise PasskeyProtocolError(f"Okta IDX assertion failed: HTTP {response.status_code}: {response.text[:1000]}")
    payload = response.json()
    if not payload.get("success"):
        raise PasskeyProtocolError("Okta rejected the passkey assertion.")
    return {"success": True, "credentialId": str(credential["credentialId"]), "successStep": (payload.get("success") or {}).get("name")}
