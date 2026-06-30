from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote, urlencode, urljoin

CLIENT_ID = "19db86c3-b2b9-44cc-b339-36da233a3be2"
REDIRECT_URI = "https://mysignins.microsoft.com"
RP_ID = "login.microsoft.com"
TOKEN_SCOPE = f"{CLIENT_ID}/.default openid profile offline_access"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
)
SEC_CH_UA = '"Chromium";v="148", "Microsoft Edge";v="148", "Not_A Brand";v="99"'
VERIFY_FEATURE_FLAGS = (
    "tff,cpfaudit,enslfmg,fwdIam,pKoe,drmm,myAccSi,saap,mregph,mysigninsfido,"
    "mysigninsauthappnotification,mysigninsauthappotp,migaam,mrp,hoaref,mregextauth,"
    "mreghwoath,mregsq,premr,cepcr,ebtta,otebvpf,mysigninssetdefault,gcu,msieme,"
    "msiemedel,mdelsq,mdelhwoath,msidelauthapp,mdelph,msidelfido,msrappp,msdappp,"
    "aamp,fwdPhIam,fido2fs,psi2fs,sve,gprp,ctumaru,dhwo,legacyHwOATH,epowe,asnmfc,"
    "ppre,sspuispid,mahfc,pkrce,miseclientid,fnmosia,essvc,etmosvc,enmosia,enmosiv,"
    "enmosid,enmosisd,enmosidht,enmosiima,enmopr,asnmtabr,onmfrc,eaieci,enlnb,"
    "esiastnb,ersiemfa,duc,stffrf,svfae,gcufa,gprpfa,umarufnc,mfarae,gefmassv"
)


class PasskeyError(Exception):
    pass


class PasskeyValidationError(PasskeyError):
    pass


class PasskeySecurityError(PasskeyError):
    pass


class PasskeyProtocolError(PasskeyError):
    pass


@dataclass(frozen=True)
class TokenBundle:
    access_token: str
    refresh_token: str | None
    tenant_id: str | None
    user_principal_name: str | None


@dataclass(frozen=True)
class SessionAuthorization:
    session_ctx_v2: str
    require_ngc_mfa: bool


@dataclass(frozen=True)
class CreationRequest:
    canary: str
    server_challenge: str
    post_back_url: str | None
    provision_url: str | None
    user_id: str
    exclude_credentials_json: str | None


@dataclass(frozen=True)
class AttestationPayload:
    credential_id_b64url: str
    client_data_json_b64url: str
    attestation_object_b64url: str
    extension_results_b64url: str
    user_handle: str
    rp_id: str = RP_ID


@dataclass(frozen=True)
class KeyVaultKeyMaterial:
    key_name: str
    key_id: str
    public_key_x: bytes
    public_key_y: bytes


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def build_form_body(fields: dict[str, object]) -> str:
    filtered = []
    for key, value in fields.items():
        if value is None:
            continue
        string_value = str(value)
        if string_value == "":
            filtered.append((key, string_value))
            continue
        filtered.append((key, string_value))
    return urlencode(filtered)


def generate_pkce_pair() -> tuple[str, str]:
    verifier = b64url_encode(secrets.token_bytes(32))
    challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def parse_ests_config(content: str) -> dict[str, object] | None:
    match = re.search(r"\$Config=(\{.*?\});", content, flags=re.DOTALL)
    if not match:
        return None
    return json.loads(match.group(1))


def extract_hidden_form(content: str) -> tuple[str | None, OrderedDict[str, str]]:
    action_match = re.search(r'action="([^"]+)"', content)
    action = action_match.group(1) if action_match else None
    payload: OrderedDict[str, str] = OrderedDict()
    for field in re.finditer(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', content):
        payload[field.group(1)] = html.unescape(field.group(2))
    return action, payload


def resolve_absolute_url(base_url: str, location: str) -> str:
    if re.match(r"^https?://", location):
        return location
    return urljoin(base_url, location)


def extract_data_content(content: str, element_id: str) -> str | None:
    match = re.search(
        rf'<div\s+id="{re.escape(element_id)}"\s+data-content="([^"]*)"',
        content,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return html.unescape(match.group(1))


def sanitize_upn_prefix(user_principal_name: str) -> str:
    prefix = user_principal_name.split("@", 1)[0]
    sanitized = re.sub(r"[^0-9A-Za-z-]", "", prefix)
    return sanitized or "user"


def build_key_name(user_principal_name: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"passkey-{sanitize_upn_prefix(user_principal_name)}-{timestamp}"


def add_browser_headers(headers: dict[str, str], fetch_site: str = "same-origin") -> dict[str, str]:
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Accept-Language", "en-US")
    headers.setdefault("sec-ch-ua", SEC_CH_UA)
    headers.setdefault("sec-ch-ua-mobile", "?0")
    headers.setdefault("sec-ch-ua-platform", '"Windows"')
    headers.setdefault("Sec-Fetch-Dest", "empty")
    headers.setdefault("Sec-Fetch-Mode", "cors")
    headers.setdefault("Sec-Fetch-Site", fetch_site)
    return headers


def build_spa_headers() -> dict[str, str]:
    return {
        "Origin": REDIRECT_URI,
        "Referer": f"{REDIRECT_URI}/",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Dest": "empty",
    }


def build_session_headers(
    access_token: str,
    client_session_id: str,
    *,
    session_ctx_v2: str | None = None,
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Origin": REDIRECT_URI,
        "Referer": f"{REDIRECT_URI}/security-info",
        "AjaxRequest": "true",
        "x-ms-mysignins-region": "westus2",
        "x-ms-client-session-id": client_session_id,
    }
    if session_ctx_v2:
        headers["SessionCtxV2"] = session_ctx_v2
    return headers


def decode_jwt_payload(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) < 2:
        raise PasskeyProtocolError("Token did not contain a JWT payload.")
    return json.loads(b64url_decode(parts[1]).decode("utf-8"))


def extract_user_principal_name(claims: dict[str, object]) -> str | None:
    for key in ("upn", "preferred_username", "unique_name"):
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def quoted(value: str) -> str:
    return quote(value, safe="")


def new_state() -> str:
    return str(uuid.uuid4())
