from __future__ import annotations

import json
import re
import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .common import (
    PasskeyProtocolError,
    PasskeyValidationError,
    RP_ID,
    USER_AGENT,
    b64url_decode,
    b64url_encode,
    configure_requests_session,
    normalize_user_agent,
    parse_ests_config,
)
from .keyvault import get_key_vault_access_token

DEFAULT_AUTH_URL = (
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    "?response_type=code"
    "&redirect_uri=msauth.com.msauth.unsignedapp://auth"
    "&scope=https://graph.microsoft.com/.default"
    "&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46"
)


@dataclass(frozen=True)
class PasskeyLoginResult:
    success: bool
    user_principal_name: str
    signature_method: str
    cookie_type: str | None
    cookie_value: str | None
    key_vault_name: str | None


def load_credential_record(
    *,
    credential_path: str,
    key_vault_name: str | None = None,
    key_vault_key_name: str | None = None,
) -> dict[str, Any]:
    with open(credential_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if key_vault_name or key_vault_key_name:
        payload.setdefault("keyVault", {})
        if key_vault_name:
            payload["keyVault"]["vaultName"] = key_vault_name
        if key_vault_key_name:
            payload["keyVault"]["keyName"] = key_vault_key_name

    return payload


def authenticate_with_passkey(
    *,
    credential: dict[str, Any],
    key_vault_access_token: str | None = None,
    key_vault_managed_identity_client_id: str | None = None,
    key_vault_client_id: str | None = None,
    key_vault_client_secret: str | None = None,
    key_vault_tenant_id: str | None = None,
    auth_url: str = DEFAULT_AUTH_URL,
    user_agent: str = USER_AGENT,
    proxy: str | None = None,
) -> PasskeyLoginResult:
    target_user = _get_required_string(credential, "userName", "username", "userPrincipalName")
    user_handle = _normalize_base64url(_get_required_string(credential, "userHandle"))
    credential_id = _normalize_credential_id(_get_required_string(credential, "credentialId"))
    relying_party = credential.get("relyingParty") or credential.get("rpId") or RP_ID
    origin_url = credential.get("url") or f"https://{relying_party}"
    sign_count = int(credential.get("signCount") or credential.get("counter") or 0)

    key_vault_info = credential.get("keyVault") if isinstance(credential.get("keyVault"), dict) else None
    use_key_vault = key_vault_info is not None

    private_key_pem = None
    if not use_key_vault:
        raw_key = credential.get("privateKey") or credential.get("keyValue")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise PasskeyValidationError(
                "Credential did not contain a Key Vault reference or a local private key."
            )
        private_key_pem = _normalize_private_key_pem(raw_key)

    normalized_user_agent = normalize_user_agent(user_agent)
    session = configure_requests_session(requests.Session(), normalized_user_agent)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    _validate_auth_url(auth_url)
    auth_url = _ensure_query_parameter(auth_url, "sso_reload", "true")
    auth_url = _ensure_query_parameter(auth_url, "login_hint", target_user)

    kv_token = None
    if use_key_vault:
        kv_token = get_key_vault_access_token(
            configured_token=key_vault_access_token,
            managed_identity_client_id=key_vault_managed_identity_client_id,
            azure_cli_tenant_id=key_vault_tenant_id,
            client_id=key_vault_client_id,
            client_secret=key_vault_client_secret,
            tenant_id=key_vault_tenant_id,
        )

    session_info = _extract_json_payload(
        session.get(auth_url, allow_redirects=False, timeout=60).text,
        "initial authorize response",
    )
    has_fido = bool(
        (((session_info.get("oGetCredTypeResult") or {}).get("Credentials") or {}).get("HasFido"))
    )
    if not has_fido or not session_info.get("sFidoChallenge"):
        raise PasskeyProtocolError("FIDO2 authentication not available for this user.")

    auth_data = _new_authenticator_data(relying_party, sign_count)
    challenge = b64url_encode(str(session_info["sFidoChallenge"]).encode("ascii"))
    origin = f"https://{urlparse(origin_url).hostname or relying_party}"
    client_data_json = json.dumps(
        OrderedDict(
            (
                ("challenge", challenge),
                ("crossOrigin", False),
                ("origin", origin),
                ("type", "webauthn.get"),
            )
        ),
        separators=(",", ":"),
    ).encode("utf-8")
    signature = _new_fido_signature(
        challenge=challenge,
        origin=origin,
        auth_data=auth_data,
        client_data_json=client_data_json,
        key_vault_info=key_vault_info,
        key_vault_token=kv_token,
        private_key_pem=private_key_pem,
        user_agent=normalized_user_agent,
    )

    fido_payload = OrderedDict(
        (
            ("id", credential_id),
            ("clientDataJSON", b64url_encode(client_data_json)),
            ("authenticatorData", b64url_encode(auth_data)),
            ("signature", b64url_encode(signature)),
            ("userHandle", user_handle),
        )
    )

    allow_list = (
        ((((session_info.get("oGetCredTypeResult") or {}).get("Credentials") or {}).get("FidoParams") or {}).get("AllowList"))
        or []
    )
    credentials_json = ",".join(str(value) for value in allow_list)

    pre_verify = session.post(
        "https://login.microsoft.com/common/fido/get?uiflavor=Web",
        data={
            "allowedIdentities": 2,
            "canary": session_info["sFT"],
            "ServerChallenge": session_info["sFT"],
            "postBackUrl": session_info["urlPost"],
            "postBackUrlAad": session_info["urlPostAad"],
            "postBackUrlMsa": session_info["urlPostMsa"],
            "cancelUrl": session_info["urlRefresh"],
            "resumeUrl": session_info["urlResume"],
            "correlationId": session_info["correlationId"],
            "credentialsJson": credentials_json,
            "ctx": session_info["sCtx"],
            "username": target_user,
            "loginCanary": session_info["canary"],
        },
        allow_redirects=False,
        timeout=60,
    )
    if pre_verify.status_code >= 400:
        raise PasskeyProtocolError(
            f"Pre-verification failed: HTTP {pre_verify.status_code}. ResponseBody={pre_verify.text[:1000]}"
        )
    response_info = _extract_json_payload(pre_verify.text, "pre-verification response")

    payload = {
        "type": 23,
        "ps": 23,
        "assertion": json.dumps(fido_payload, separators=(",", ":"), ensure_ascii=False),
        "lmcCanary": response_info["sCrossDomainCanary"],
        "hpgrequestid": response_info["sessionId"],
        "ctx": response_info["sCtx"],
        "canary": response_info["canary"],
        "flowToken": response_info["sFT"],
    }

    login_response = session.post(
        "https://login.microsoftonline.com/common/login",
        data=payload,
        allow_redirects=False,
        timeout=60,
    )
    if use_key_vault:
        time.sleep(0.5)

    payload["flowToken"] = (((session_info.get("oGetCredTypeResult") or {}).get("FlowToken")))
    login_response = session.post(
        "https://login.microsoftonline.com/common/login?sso_reload=true",
        data=payload,
        allow_redirects=False,
        timeout=60,
    )
    if use_key_vault:
        time.sleep(0.5)

    debug = _try_extract_json_payload(login_response.text)
    current_page_id = debug.get("pgid") if isinstance(debug, dict) else None
    last_page_id = None
    loop_count = 0
    last_response = login_response

    while isinstance(debug, dict) and debug.get("pgid") in {"CmsiInterrupt", "KmsiInterrupt", "ConvergedSignIn"}:
        if (current_page_id == last_page_id and current_page_id != "ConvergedSignIn") or loop_count >= 10:
            raise PasskeyProtocolError(
                "Authentication failed: stuck in interrupt loop during FIDO2 validation. "
                f"currentPageId={current_page_id!r}; lastPageId={last_page_id!r}; loopCount={loop_count}."
            )

        last_page_id = current_page_id
        loop_count += 1
        page_id = debug["pgid"]
        if page_id == "CmsiInterrupt":
            response = session.post(
                "https://login.microsoftonline.com/appverify",
                data={
                    "ContinueAuth": "true",
                    "i19": 4130,
                    "canary": debug.get("canary", ""),
                    "iscsrfspeedbump": "false",
                    "flowToken": debug.get("sFT", ""),
                    "hpgrequestid": debug.get("correlationId", ""),
                    "ctx": debug.get("sCtx", ""),
                },
                allow_redirects=False,
                timeout=60,
            )
        elif page_id == "KmsiInterrupt":
            response = session.post(
                "https://login.microsoftonline.com/kmsi",
                data={
                    "LoginOptions": 1,
                    "type": 28,
                    "ctx": debug.get("sCtx", ""),
                    "hpgrequestid": debug.get("correlationId", ""),
                    "flowToken": debug.get("sFT", ""),
                    "canary": debug.get("canary", ""),
                    "i19": 4130,
                },
                allow_redirects=False,
                timeout=60,
            )
        else:
            session_id = debug.get("sessionId")
            arr_sessions = debug.get("arrSessions") or []
            if isinstance(arr_sessions, list) and arr_sessions and isinstance(arr_sessions[0], dict):
                session_id = arr_sessions[0].get("id") or session_id
            response = session.get(
                f"{debug.get('urlLogin', '')}&sessionid={session_id}",
                allow_redirects=False,
                timeout=60,
            )

        last_response = response
        time.sleep(0.3)
        location = response.headers.get("Location")
        if response.status_code in (301, 302, 303, 307, 308) and location:
            last_response = _follow_completion_redirects(session, response)
            break
        debug = _try_extract_json_payload(response.text)
        current_page_id = debug.get("pgid") if isinstance(debug, dict) else None

    if use_key_vault:
        time.sleep(0.5)

    _follow_completion_redirects(session, last_response)
    ests_cookies = [cookie for cookie in session.cookies if cookie.name.startswith("ESTS")]
    if not ests_cookies:
        return PasskeyLoginResult(
            success=False,
            user_principal_name=target_user,
            signature_method="Azure Key Vault" if use_key_vault else "Local Private Key",
            cookie_type=None,
            cookie_value=None,
            key_vault_name=(key_vault_info or {}).get("vaultName"),
        )

    ests_cookie = sorted(ests_cookies, key=lambda cookie: len(cookie.value), reverse=True)[0]
    return PasskeyLoginResult(
        success=True,
        user_principal_name=target_user,
        signature_method="Azure Key Vault" if use_key_vault else "Local Private Key",
        cookie_type=ests_cookie.name,
        cookie_value=ests_cookie.value,
        key_vault_name=(key_vault_info or {}).get("vaultName"),
    )


def _get_required_string(payload: dict[str, Any], *names: str) -> str:
    for name in names:
        value = payload.get(name)
        if isinstance(value, str) and value:
            return value
    raise PasskeyValidationError(f"Credential is missing required field(s): {', '.join(names)}")


def _normalize_base64url(value: str) -> str:
    return value.strip().replace("+", "-").replace("/", "_").rstrip("=")


def _normalize_credential_id(value: str) -> str:
    lowered = value.lower()
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lowered):
        raw = bytes.fromhex(lowered.replace("-", ""))
        return b64url_encode(raw)
    return _normalize_base64url(value)


def _normalize_private_key_pem(value: str) -> str:
    stripped = value.strip()
    if "BEGIN PRIVATE KEY" in stripped:
        return stripped
    wrapped = "\n".join(stripped[i : i + 64] for i in range(0, len(stripped), 64))
    return f"-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----"


def _validate_auth_url(auth_url: str) -> None:
    parsed = urlparse(auth_url)
    if parsed.scheme != "https" or parsed.netloc != "login.microsoftonline.com":
        raise PasskeyValidationError(f"Auth URL must start with 'https://login.microsoftonline.com/'. Current: {auth_url}")
    query = dict((part.split("=", 1) + [""])[:2] for part in parsed.query.split("&") if part)
    for required in ("client_id", "response_type", "redirect_uri"):
        if required not in query:
            raise PasskeyValidationError(f"Auth URL is missing required parameter '{required}'.")


def _ensure_query_parameter(auth_url: str, name: str, value: str) -> str:
    parsed = urlparse(auth_url)
    if re.search(rf"(^|[?&]){re.escape(name)}=", auth_url):
        return auth_url
    delimiter = "&" if parsed.query else "?"
    return f"{auth_url}{delimiter}{urlencode({name: value})}"


def _follow_completion_redirects(session: requests.Session, response: requests.Response | None, max_hops: int = 10) -> requests.Response | None:
    current = response
    hops = 0
    while current is not None and current.status_code in (301, 302, 303, 307, 308) and hops < max_hops:
        location = current.headers.get("Location")
        if not location:
            break
        next_url = urljoin(current.url, location)
        parsed = urlparse(next_url)
        if parsed.scheme not in {"http", "https"}:
            break
        current = session.get(next_url, allow_redirects=False, timeout=60)
        hops += 1
    return current


def _extract_json_payload(content: str, label: str) -> dict[str, Any]:
    payload = _try_extract_json_payload(content)
    if not isinstance(payload, dict):
        raise PasskeyProtocolError(f"Unexpected response format from {label}.")
    return payload


def _try_extract_json_payload(content: str) -> dict[str, Any] | None:
    config_payload = parse_ests_config(content)
    if isinstance(config_payload, dict):
        return config_payload
    match = re.search(r"{.*}", content, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _new_authenticator_data(relying_party: str, sign_count: int) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(relying_party.encode("utf-8"))
    rp_id_hash = digest.finalize()
    return rp_id_hash + bytes([0x05]) + int(sign_count).to_bytes(4, "big")


def _new_fido_signature(
    *,
    challenge: str,
    origin: str,
    auth_data: bytes,
    client_data_json: bytes,
    key_vault_info: dict[str, Any] | None,
    key_vault_token: str | None,
    private_key_pem: str | None,
    user_agent: str,
) -> bytes:
    del challenge
    del origin
    client_hash = hashes.Hash(hashes.SHA256())
    client_hash.update(client_data_json)
    combined = auth_data + client_hash.finalize()
    data_hash = hashes.Hash(hashes.SHA256())
    data_hash.update(combined)
    digest = data_hash.finalize()

    if key_vault_info and key_vault_token:
        sign_uri = (
            f"https://{key_vault_info['vaultName']}.vault.azure.net/keys/"
            f"{key_vault_info['keyName']}/sign?api-version=7.4"
        )
        response = requests.post(
            sign_uri,
            headers={
                "Authorization": f"Bearer {key_vault_token}",
                "Content-Type": "application/json",
                "User-Agent": normalize_user_agent(user_agent),
            },
            json={
                "alg": "ES256",
                "value": b64url_encode(digest),
            },
            timeout=60,
        )
        if not response.ok:
            raise PasskeyProtocolError(
                f"Key Vault signing failed: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
            )
        signature_bytes = b64url_decode(response.json()["value"])
        if len(signature_bytes) != 64:
            raise PasskeyProtocolError(
                f"Invalid IEEE P1363 signature length: {len(signature_bytes)}. Expected 64 bytes for ES256."
            )
        return _convert_ieee_to_der(signature_bytes)

    if not private_key_pem:
        raise PasskeyValidationError("No signing material was available for passkey authentication.")

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise PasskeyValidationError("Credential private key is not an EC private key.")
    return private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def _convert_ieee_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise PasskeyValidationError(f"Invalid IEEE P1363 signature length: {len(signature)}.")
    r = signature[:32]
    s = signature[32:]
    return utils.encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s, "big"))
