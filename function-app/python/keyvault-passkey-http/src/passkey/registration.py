from __future__ import annotations

import json
import secrets
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .common import (
    AttestationPayload,
    CLIENT_ID,
    CreationRequest,
    KeyVaultKeyMaterial,
    PasskeyProtocolError,
    PasskeySecurityError,
    PasskeyValidationError,
    REDIRECT_URI,
    RP_ID,
    VERIFY_FEATURE_FLAGS,
    add_browser_headers,
    b64url_encode,
    build_form_body,
    build_key_name,
    build_session_headers,
    parse_ests_config,
    generate_pkce_pair,
    extract_data_content,
)
from .entra_auth import (
    authorize_mysignins_session,
    exchange_auth_code_for_tokens,
    refresh_tokens_with_ngcmfa,
    silent_auth_with_ests_cookie,
    tap_pkce_login,
)
from .keyvault import create_ec_key, get_key_vault_access_token


@dataclass(frozen=True)
class PasskeyAppConfig:
    tenant_id: str
    key_vault_name: str
    managed_identity_client_id: str | None
    key_vault_access_token: str | None


def load_config_from_environment() -> PasskeyAppConfig:
    import os

    tenant_id = os.getenv("PASSKEY_TENANT_ID")
    key_vault_name = os.getenv("PASSKEY_KEYVAULT_NAME")
    if not tenant_id:
        raise PasskeyValidationError("Missing required setting 'PASSKEY_TENANT_ID'.")
    if not key_vault_name:
        raise PasskeyValidationError("Missing required setting 'PASSKEY_KEYVAULT_NAME'.")

    return PasskeyAppConfig(
        tenant_id=tenant_id,
        key_vault_name=key_vault_name,
        managed_identity_client_id=os.getenv("PASSKEY_MANAGED_IDENTITY_CLIENT_ID"),
        key_vault_access_token=os.getenv("PASSKEY_KEYVAULT_ACCESS_TOKEN"),
    )


def register_passkey_via_tap(
    *,
    config: PasskeyAppConfig,
    user_principal_name: str,
    tap: str,
    display_name: str = "Software Passkey",
    key_vault_key_name: str | None = None,
) -> dict[str, Any]:
    if not user_principal_name:
        raise PasskeyValidationError("Missing required field 'userPrincipalName' or 'email'.")
    if not tap:
        raise PasskeyValidationError("Missing required field 'tap' or 'temporaryAccessPass'.")

    session = requests.Session()
    code_verifier, code_challenge = generate_pkce_pair()
    auth_code = tap_pkce_login(
        session=session,
        authority=config.tenant_id,
        user_principal_name=user_principal_name,
        tap=tap,
        code_challenge=code_challenge,
    )
    tokens = exchange_auth_code_for_tokens(
        session=session,
        authority=config.tenant_id,
        auth_code=auth_code,
        code_verifier=code_verifier,
        include_ngcmfa_claims=True,
    )
    if not tokens.refresh_token:
        raise PasskeyProtocolError("Token exchange did not return a refresh token.")

    return _complete_registration(
        session=session,
        config=config,
        tenant_id=tokens.tenant_id or config.tenant_id,
        user_principal_name=user_principal_name,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        display_name=display_name,
        key_vault_key_name=key_vault_key_name,
    )


def register_passkey_via_ests_auth(
    *,
    config: PasskeyAppConfig,
    requested_user_principal_name: str,
    ests_auth_cookie: str,
    display_name: str = "Software Passkey",
    key_vault_key_name: str | None = None,
) -> dict[str, Any]:
    if not requested_user_principal_name:
        raise PasskeyValidationError("Missing required field 'userPrincipalName' or 'email'.")
    if not ests_auth_cookie:
        raise PasskeyValidationError("Missing required field 'estsAuth' or 'estsAuthCookie'.")

    session = requests.Session()
    code_verifier, code_challenge = generate_pkce_pair()
    auth_code = silent_auth_with_ests_cookie(
        session=session,
        authority=config.tenant_id,
        ests_auth_cookie=ests_auth_cookie,
        code_challenge=code_challenge,
    )
    tokens = exchange_auth_code_for_tokens(
        session=session,
        authority=config.tenant_id,
        auth_code=auth_code,
        code_verifier=code_verifier,
        include_ngcmfa_claims=False,
    )
    if not tokens.refresh_token:
        raise PasskeyProtocolError("Token exchange did not return a refresh token.")
    resolved_user_principal_name = tokens.user_principal_name
    if not resolved_user_principal_name:
        raise PasskeyProtocolError("Could not extract a user principal name from the ESTSAUTH token.")
    if resolved_user_principal_name.casefold() != requested_user_principal_name.casefold():
        raise PasskeySecurityError(
            f"The ESTSAUTH cookie resolved to '{resolved_user_principal_name}', "
            f"which does not match the requested user '{requested_user_principal_name}'."
        )

    return _complete_registration(
        session=session,
        config=config,
        tenant_id=tokens.tenant_id or config.tenant_id,
        user_principal_name=resolved_user_principal_name,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        display_name=display_name,
        key_vault_key_name=key_vault_key_name,
    )


def _complete_registration(
    *,
    session: requests.Session,
    config: PasskeyAppConfig,
    tenant_id: str,
    user_principal_name: str,
    access_token: str,
    refresh_token: str,
    display_name: str,
    key_vault_key_name: str | None,
) -> dict[str, Any]:
    key_name = key_vault_key_name or build_key_name(user_principal_name)
    key_vault_token = get_key_vault_access_token(
        configured_token=config.key_vault_access_token,
        managed_identity_client_id=config.managed_identity_client_id,
    )
    key_material = create_ec_key(
        session=session,
        key_vault_name=config.key_vault_name,
        key_name=key_name,
        access_token=key_vault_token,
    )

    client_session_id = str(uuid.uuid4())
    session_authorization = authorize_mysignins_session(
        session=session,
        access_token=access_token,
        client_session_id=client_session_id,
    )
    if session_authorization.require_ngc_mfa:
        refreshed = refresh_tokens_with_ngcmfa(
            session=session,
            tenant_id=tenant_id,
            refresh_token=refresh_token,
        )
        access_token = refreshed.access_token
        refresh_token = refreshed.refresh_token or refresh_token
        session_authorization = authorize_mysignins_session(
            session=session,
            access_token=access_token,
            client_session_id=client_session_id,
        )

    creation_request = _request_passkey_creation(
        session=session,
        access_token=access_token,
        session_ctx_v2=session_authorization.session_ctx_v2,
        client_session_id=client_session_id,
    )
    attestation = _build_attestation(
        public_key=key_material,
        server_challenge=creation_request.server_challenge,
        user_handle=creation_request.user_id,
    )
    correlation_id = str(uuid.uuid4())
    _register_server_challenge(
        session=session,
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        creation_request=creation_request,
        user_principal_name=user_principal_name,
        display_name=display_name,
    )
    canary = _submit_newfido(
        session=session,
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        creation_request=creation_request,
        attestation=attestation,
    )
    session_ctx_v2 = session_authorization.session_ctx_v2
    try:
        session_ctx_v2 = authorize_mysignins_session(
            session=session,
            access_token=access_token,
            client_session_id=client_session_id,
            session_ctx_v2=session_ctx_v2,
            body="{}",
        ).session_ctx_v2
    except PasskeyProtocolError:
        pass

    _verify_registration(
        session=session,
        access_token=access_token,
        session_ctx_v2=session_ctx_v2,
        client_session_id=client_session_id,
        canary=canary,
        attestation=attestation,
        display_name=display_name,
    )

    return {
        "credentialId": attestation.credential_id_b64url,
        "relyingParty": RP_ID,
        "url": f"https://{RP_ID}",
        "userName": user_principal_name,
        "userHandle": creation_request.user_id,
        "displayName": display_name,
        "keyVault": {
            "vaultName": config.key_vault_name,
            "keyName": key_material.key_name,
            "keyId": key_material.key_id,
        },
        "createdDateTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _request_passkey_creation(
    *,
    session: requests.Session,
    access_token: str,
    session_ctx_v2: str,
    client_session_id: str,
) -> CreationRequest:
    headers = add_browser_headers(
        build_session_headers(
            access_token,
            client_session_id,
            session_ctx_v2=session_ctx_v2,
        )
    )
    response = session.post(
        f"{REDIRECT_URI}/api/authenticationmethods/new",
        data='{"Type":18}',
        headers={**headers, "Content-Type": "application/json"},
        timeout=60,
    )
    if not response.ok:
        response_headers = {}
        for header_name in (
            "x-ms-request-id",
            "x-ms-ests-server",
            "WWW-Authenticate",
            "x-ms-diagnostics",
            "Retry-After",
            "x-ms-srs",
        ):
            header_value = response.headers.get(header_name)
            if header_value:
                response_headers[header_name] = header_value
        raise PasskeyProtocolError(
            "authenticationmethods/new failed: "
            f"HTTP {response.status_code}. "
            f"ResponseHeaders={json.dumps(response_headers, separators=(',', ':')) or '(none)'}; "
            f"ResponseBody={response.text[:1000] or '(empty)'}"
        )

    payload = response.json()
    if payload.get("ErrorCode") not in (None, 0):
        raise PasskeyProtocolError(f"authenticationmethods/new returned ErrorCode {payload.get('ErrorCode')}")

    inner_json = payload.get("Data")
    if isinstance(inner_json, str):
        inner_json = json.loads(inner_json)
    request_data = inner_json["requestData"]
    canary = request_data.get("canary")
    server_challenge = request_data.get("serverChallenge")
    user_id = request_data.get("userId")
    if not canary:
        raise PasskeyProtocolError("Failed to get canary from authenticationmethods/new response.")
    if not server_challenge:
        raise PasskeyProtocolError("No serverChallenge returned from authenticationmethods/new.")
    if not user_id:
        raise PasskeyProtocolError("No userId returned from authenticationmethods/new.")

    return CreationRequest(
        canary=canary,
        server_challenge=server_challenge,
        post_back_url=request_data.get("postBackUrl"),
        provision_url=inner_json.get("provisionUrl"),
        user_id=user_id,
        exclude_credentials_json=request_data.get("ExcludeNextGenCredentialsJSON"),
    )


def _build_attestation(
    *,
    public_key: KeyVaultKeyMaterial,
    server_challenge: str,
    user_handle: str,
) -> AttestationPayload:
    credential_id = secrets.token_bytes(32)
    credential_id_b64url = b64url_encode(credential_id)

    cose_key = OrderedDict(
        (
            (1, 2),
            (3, -7),
            (-1, 1),
            (-2, public_key.public_key_x),
            (-3, public_key.public_key_y),
        )
    )
    cose_key_bytes = cbor2.dumps(cose_key, canonical=False)

    rp_id_hash = hashes.Hash(hashes.SHA256())
    rp_id_hash.update(RP_ID.encode("utf-8"))
    auth_data = (
        rp_id_hash.finalize()
        + bytes([0x45])
        + b"\x00\x00\x00\x00"
        + b"\x00" * 16
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cose_key_bytes
    )

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64url_encode(server_challenge.encode("utf-8")),
            "origin": f"https://{RP_ID}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    client_data_hash = hashes.Hash(hashes.SHA256())
    client_data_hash.update(client_data_json)
    signature_base = auth_data + client_data_hash.finalize()

    batch_private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Batch Certificate"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chromium"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    batch_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(batch_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2017, 7, 14, 2, 40, 0, tzinfo=UTC))
        .not_valid_after(datetime(2046, 2, 6, 6, 33, 7, tzinfo=UTC))
        .sign(batch_private_key, hashes.SHA256())
    )
    signature_bytes = batch_private_key.sign(signature_base, ec.ECDSA(hashes.SHA256()))
    batch_certificate_der = batch_certificate.public_bytes(encoding=serialization.Encoding.DER)

    attestation_object = OrderedDict(
        (
            ("fmt", "packed"),
            (
                "attStmt",
                OrderedDict(
                    (
                        ("alg", -7),
                        ("sig", signature_bytes),
                        ("x5c", [batch_certificate_der]),
                    )
                ),
            ),
            ("authData", auth_data),
        )
    )

    extension_results_b64url = b64url_encode(b'{"hmacCreateSecret":false}')
    return AttestationPayload(
        credential_id_b64url=credential_id_b64url,
        client_data_json_b64url=b64url_encode(client_data_json),
        attestation_object_b64url=b64url_encode(cbor2.dumps(attestation_object, canonical=False)),
        extension_results_b64url=extension_results_b64url,
        user_handle=user_handle,
    )


def _register_server_challenge(
    *,
    session: requests.Session,
    tenant_id: str,
    correlation_id: str,
    creation_request: CreationRequest,
    user_principal_name: str,
    display_name: str,
) -> None:
    post_back_url = creation_request.post_back_url or f"{REDIRECT_URI}/api/post/newfido"
    body = OrderedDict(
        (
            ("correlationId", correlation_id),
            ("canary", creation_request.canary),
            ("ExcludeNextGenCredentialsJSON", creation_request.exclude_credentials_json or "[]"),
            ("memberName", user_principal_name),
            ("postBackUrl", f"{post_back_url}?mysignins-region=westus2&cid={correlation_id}"),
            ("serverChallenge", creation_request.server_challenge),
            ("userDisplayName", display_name),
            ("userIconUrl", ""),
            ("userId", creation_request.user_id),
        )
    )
    fido_create_url = creation_request.provision_url or f"https://login.microsoft.com/{tenant_id}/fido/create"
    fido_create_url = f"{fido_create_url}?cid={correlation_id}"
    try:
        session.post(
            fido_create_url,
            data=build_form_body(body),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=60,
        )
    except requests.RequestException:
        return


def _submit_newfido(
    *,
    session: requests.Session,
    tenant_id: str,
    correlation_id: str,
    creation_request: CreationRequest,
    attestation: AttestationPayload,
) -> str:
    if creation_request.post_back_url:
        if "?" in creation_request.post_back_url:
            new_fido_url = creation_request.post_back_url
        else:
            new_fido_url = f"{creation_request.post_back_url}?mysignins-region=westus2&cid={correlation_id}"
    else:
        new_fido_url = f"{REDIRECT_URI}/api/post/newfido?mysignins-region=westus2&cid={correlation_id}"

    body = OrderedDict(
        (
            ("canary", creation_request.canary),
            ("authenticator", "cross-platform"),
            ("transports", "usb"),
            ("aaguid", "00000000-0000-0000-0000-000000000000"),
            ("credentialDeviceType", "singleDevice"),
            ("credentialBackedUp", "false"),
            ("attestationParseError", ""),
            ("error_code", ""),
            ("suberror_code", ""),
            ("clientDataJson", attestation.client_data_json_b64url),
            ("attestationObject", attestation.attestation_object_b64url),
            ("credentialId", attestation.credential_id_b64url),
            ("clientExtensionResults", attestation.extension_results_b64url),
            ("i19", ""),
        )
    )

    response = session.post(
        new_fido_url,
        data=build_form_body(body),
        headers={
            "Origin": f"https://{RP_ID}",
            "Referer": f"https://{RP_ID}/",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(
            f"newfido failed: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    response_config = parse_ests_config(response.text)
    if isinstance(response_config, dict) and response_config.get("iErrorCode") not in (None, 0):
        raise PasskeyProtocolError(f"newfido returned error code {response_config.get('iErrorCode')}")

    canary = creation_request.canary
    context_text = extract_data_content(response.text, "context")
    if context_text:
        try:
            context = json.loads(context_text)
            if isinstance(context.get("Canary"), str) and context["Canary"]:
                canary = context["Canary"]
        except json.JSONDecodeError:
            pass

    redirect_url = extract_data_content(response.text, "redirectUrl")
    if redirect_url:
        navigation_url = redirect_url.split("#", 1)[0]
        try:
            session.get(navigation_url, timeout=60)
        except requests.RequestException:
            pass

    return canary


def _verify_registration(
    *,
    session: requests.Session,
    access_token: str,
    session_ctx_v2: str,
    client_session_id: str,
    canary: str,
    attestation: AttestationPayload,
    display_name: str,
) -> None:
    verification_data = json.dumps(
        {
            "Name": display_name,
            "Canary": canary,
            "AttestationObject": attestation.attestation_object_b64url,
            "ClientDataJson": attestation.client_data_json_b64url,
            "CredentialId": attestation.credential_id_b64url,
            "ClientExtensionResults": attestation.extension_results_b64url,
            "PostInfo": "",
            "AAGuid": "00000000-0000-0000-0000-000000000000",
            "CredentialDeviceType": "singleDevice",
        },
        separators=(",", ":"),
    )
    verify_body = json.dumps(
        {
            "Type": 18,
            "VerificationData": verification_data,
        },
        separators=(",", ":"),
    )
    headers = add_browser_headers(
        {
            "Authorization": f"Bearer {access_token}",
            "SessionCtxV2": session_ctx_v2,
            "Origin": REDIRECT_URI,
            "Referer": f"{REDIRECT_URI}/security-info",
            "AjaxRequest": "true",
            "x-ms-mysignins-region": "westus2",
            "x-ms-client-session-id": client_session_id,
            "x-rff": VERIFY_FEATURE_FLAGS,
            "Content-Type": "application/json",
        }
    )

    response = session.post(
        f"{REDIRECT_URI}/api/authenticationmethods/verify",
        data=verify_body,
        headers=headers,
        timeout=60,
    )
    verify_json: dict[str, Any] | None = None
    if response.text:
        try:
            verify_json = response.json()
        except json.JSONDecodeError:
            verify_json = None

    if not response.ok:
        body = response.text[:1000] if response.text else "(empty)"
        if verify_json:
            body = json.dumps(verify_json, separators=(",", ":"))
        raise PasskeyProtocolError(f"verify failed: HTTP {response.status_code}. ResponseBody={body}")

    if not verify_json:
        raise PasskeyProtocolError("verify did not return JSON.")
    if verify_json.get("ErrorCode") not in (None, 0):
        raise PasskeyProtocolError(
            "verify returned an error: "
            f"ErrorCode={verify_json.get('ErrorCode')} "
            f"VerificationState={verify_json.get('VerificationState')} "
            f"ErrorType={verify_json.get('ErrorType')}"
        )
    if verify_json.get("VerificationState") != 2:
        raise PasskeyProtocolError(
            f"Registration failed with VerificationState={verify_json.get('VerificationState')}."
        )
