from __future__ import annotations

import argparse
import json
import secrets
import sys
from collections import OrderedDict
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBRARY_ROOT = REPO_ROOT / "python" / "libraries" / "passkey" / "src"
if str(LIBRARY_ROOT) not in sys.path:
    sys.path.insert(0, str(LIBRARY_ROOT))

from passkey import authenticate_with_passkey, load_credential_record  # noqa: E402
from passkey.common import (  # noqa: E402
    PasskeyProtocolError,
    build_form_body,
    decode_jwt_payload,
    extract_hidden_form,
    generate_pkce_pair,
    parse_ests_config,
)

DEFAULT_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEFAULT_REDIRECT_URI = "msauth.com.msauth.unsignedapp://auth"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default openid profile offline_access"


def build_authorize_url(
    *, tenant_id: str, client_id: str, redirect_uri: str, scope: str, prompt: str = "login"
) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?" + urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": scope,
            "prompt": prompt,
        }
    )


def _resolve_location(base_url: str, location: str) -> str:
    if urlparse(location).scheme:
        return location
    return urljoin(base_url, location)


def _extract_code_or_error(location: str) -> tuple[str | None, str | None]:
    parsed = urlparse(location)
    values = parse_qs(parsed.fragment or parsed.query)
    if values.get("code"):
        return values["code"][0], None
    if values.get("error"):
        description = values.get("error_description", [""])[0]
        return None, f"{values['error'][0]} - {description}".strip(" -")
    return None, None


def redeem_ests_cookie_for_code(
    *,
    session: requests.Session,
    authority: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    ests_cookie: str,
    code_challenge: str,
    max_redirects: int = 10,
) -> str:
    for name in ("ESTSAUTH", "ESTSAUTHPERSISTENT"):
        session.cookies.set(name, ests_cookie, domain=".login.microsoftonline.com", path="/")

    current_url = build_authorize_url(
        tenant_id=authority,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        prompt="none",
    ) + "&" + urlencode(
        {
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(24),
        }
    )
    current_method = "GET"
    current_body = ""

    for _ in range(max_redirects):
        if current_method == "POST":
            response = session.post(
                current_url,
                data=current_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
                timeout=60,
            )
        else:
            response = session.get(current_url, allow_redirects=False, timeout=60)

        if response.status_code == 200:
            form_action, form_payload = extract_hidden_form(response.text)
            if form_action and form_payload:
                current_url = _resolve_location(current_url, form_action)
                current_method = "POST"
                current_body = build_form_body(form_payload)
                continue

            config = parse_ests_config(response.text)
            page_id = str((config or {}).get("pgid") or "unknown")
            raise PasskeyProtocolError(f"Silent authorization returned page '{page_id}' instead of a redirect.")

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                raise PasskeyProtocolError("Redirect response did not include a Location header.")
            location = _resolve_location(current_url, location)
            code, error = _extract_code_or_error(location)
            if code:
                return code
            if error:
                raise PasskeyProtocolError(f"Silent authorization failed: {error}")
            current_url = location
            current_method = "GET"
            current_body = ""
            continue

        raise PasskeyProtocolError(f"Unexpected silent authorization response: HTTP {response.status_code}.")

    raise PasskeyProtocolError(f"Silent authorization exceeded {max_redirects} redirect steps.")


def exchange_code_for_tokens(
    *,
    session: requests.Session,
    authority: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    auth_code: str,
    code_verifier: str,
) -> dict[str, object]:
    response = session.post(
        f"https://login.microsoftonline.com/{authority}/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "scope": scope,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(f"Token exchange failed: HTTP {response.status_code}.")
    payload = response.json()
    if not isinstance(payload.get("access_token"), str):
        raise PasskeyProtocolError("Token exchange did not return an access token.")
    return payload


def cookie_metadata(session: requests.Session) -> list[dict[str, object]]:
    cookies: dict[tuple[str, str], dict[str, object]] = {}
    for cookie in session.cookies:
        key = (cookie.domain or "", cookie.name)
        cookies[key] = {"name": cookie.name, "domain": cookie.domain, "length": len(cookie.value or "")}
    return [cookies[key] for key in sorted(cookies)]


def token_metadata(token: object) -> dict[str, object]:
    value = token if isinstance(token, str) else ""
    return {"present": bool(value), "length": len(value)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticate with a Key Vault-backed passkey and inspect OAuth/OIDC token metadata."
    )
    parser.add_argument("--credential-path", required=True)
    parser.add_argument("--user-principal-name")
    parser.add_argument("--tenant-id", default="organizations")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    parser.add_argument("--keyvault-name")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-tenant-id")
    args = parser.parse_args()

    credential = load_credential_record(
        credential_path=args.credential_path,
        key_vault_name=args.keyvault_name,
        key_vault_key_name=args.keyvault_key_name,
    )
    if args.user_principal_name:
        credential["userName"] = args.user_principal_name

    login_session = requests.Session()
    login_result = authenticate_with_passkey(
        credential=credential,
        key_vault_tenant_id=args.keyvault_tenant_id,
        auth_url=build_authorize_url(
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            redirect_uri=args.redirect_uri,
            scope=args.scope,
        ),
        session=login_session,
    )
    if not login_result.success or not login_result.cookie_value:
        raise PasskeyProtocolError("Passkey authentication did not return an ESTS session cookie.")

    code_verifier, code_challenge = generate_pkce_pair()
    token_session = requests.Session()
    auth_code = redeem_ests_cookie_for_code(
        session=token_session,
        authority=args.tenant_id,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        scope=args.scope,
        ests_cookie=login_result.cookie_value,
        code_challenge=code_challenge,
    )
    tokens = exchange_code_for_tokens(
        session=token_session,
        authority=args.tenant_id,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        scope=args.scope,
        auth_code=auth_code,
        code_verifier=code_verifier,
    )

    access_token = str(tokens["access_token"])
    id_token = tokens.get("id_token")
    access_claims = decode_jwt_payload(access_token)
    id_claims = decode_jwt_payload(id_token) if isinstance(id_token, str) else None
    output = OrderedDict(
        (
            ("success", True),
            ("tenantId", access_claims.get("tid") or args.tenant_id),
            ("userPrincipalName", access_claims.get("preferred_username") or login_result.user_principal_name),
            ("clientId", args.client_id),
            ("scopesRequested", args.scope),
            ("passkey", {"credentialFile": Path(args.credential_path).name, "signatureMethod": login_result.signature_method, "keyVaultName": login_result.key_vault_name}),
            ("cookies", cookie_metadata(login_session) + cookie_metadata(token_session)),
            ("accessToken", {**token_metadata(access_token), "scope": tokens.get("scope"), "tokenType": tokens.get("token_type"), "expiresIn": tokens.get("expires_in"), "claims": access_claims}),
            ("idToken", {**token_metadata(id_token), "claims": id_claims}),
            ("refreshToken", token_metadata(tokens.get("refresh_token"))),
        )
    )
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
