from __future__ import annotations

import json
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

import requests

from .common import (
    CLIENT_ID,
    REDIRECT_URI,
    TOKEN_SCOPE,
    PasskeyProtocolError,
    SessionAuthorization,
    TokenBundle,
    add_browser_headers,
    build_form_body,
    build_session_headers,
    build_spa_headers,
    decode_jwt_payload,
    extract_hidden_form,
    extract_user_principal_name,
    new_state,
    parse_ests_config,
    quoted,
    resolve_absolute_url,
)

NGC_CLAIMS = json.dumps(
    {
        "id_token": {"amr": {"essential": True, "values": ["ngcmfa"]}},
        "access_token": {"amr": {"essential": True, "values": ["ngcmfa"]}},
    },
    separators=(",", ":"),
)


def inject_ests_auth_cookie(session: requests.Session, cookie_value: str) -> None:
    session.cookies.set("ESTSAUTHPERSISTENT", cookie_value, domain=".login.microsoftonline.com", path="/")
    session.cookies.set("ESTSAUTH", cookie_value, domain=".login.microsoftonline.com", path="/")


def _extract_code_or_error(location: str) -> tuple[str | None, str | None]:
    parsed = urlparse(location)
    candidate = parsed.fragment or parsed.query
    values = parse_qs(candidate)
    if "code" in values and values["code"]:
        return values["code"][0], None
    if "error" in values and values["error"]:
        description = values.get("error_description", [""])[0]
        return None, f"{values['error'][0]} - {description}".strip()
    return None, None


def exchange_auth_code_for_tokens(
    *,
    session: requests.Session,
    authority: str,
    auth_code: str,
    code_verifier: str,
    include_ngcmfa_claims: bool,
) -> TokenBundle:
    fields = {
        "client_id": CLIENT_ID,
        "scope": TOKEN_SCOPE,
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    if include_ngcmfa_claims:
        fields["claims"] = NGC_CLAIMS

    response = session.post(
        f"https://login.microsoftonline.com/{authority}/oauth2/v2.0/token",
        data=build_form_body(fields),
        headers={
            **build_spa_headers(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(
            f"Token exchange failed: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    payload = response.json()
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    if not access_token:
        raise PasskeyProtocolError("Token exchange did not return an access token.")

    claims = decode_jwt_payload(access_token)
    tenant_id = claims.get("tid") if isinstance(claims.get("tid"), str) else None
    user_principal_name = extract_user_principal_name(claims)
    return TokenBundle(
        access_token=access_token,
        refresh_token=refresh_token,
        tenant_id=tenant_id,
        user_principal_name=user_principal_name,
    )


def refresh_tokens_with_ngcmfa(
    *,
    session: requests.Session,
    tenant_id: str,
    refresh_token: str,
) -> TokenBundle:
    response = session.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data=build_form_body(
            {
                "client_id": CLIENT_ID,
                "scope": f"{CLIENT_ID}/.default openid",
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "claims": NGC_CLAIMS,
            }
        ),
        headers={
            **build_spa_headers(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(
            f"Refresh-token exchange failed: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise PasskeyProtocolError("Refresh-token exchange did not return an access token.")

    claims = decode_jwt_payload(access_token)
    return TokenBundle(
        access_token=access_token,
        refresh_token=payload.get("refresh_token") or refresh_token,
        tenant_id=claims.get("tid") if isinstance(claims.get("tid"), str) else tenant_id,
        user_principal_name=extract_user_principal_name(claims),
    )


def authorize_mysignins_session(
    *,
    session: requests.Session,
    access_token: str,
    client_session_id: str,
    session_ctx_v2: str | None = None,
    body: str = "",
) -> SessionAuthorization:
    response = session.post(
        f"{REDIRECT_URI}/api/session/authorize",
        data=body,
        headers={
            **build_session_headers(
                access_token,
                client_session_id,
                session_ctx_v2=session_ctx_v2,
            ),
            "Content-Type": "application/json",
        },
        timeout=60,
    )
    if not response.ok:
        raise PasskeyProtocolError(
            f"session/authorize failed: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    payload = response.json()
    if not payload.get("isAuthorized"):
        raise PasskeyProtocolError(f"Session not authorized. Response={json.dumps(payload, separators=(',', ':'))}")

    session_ctx = payload.get("sessionCtxV2")
    if not isinstance(session_ctx, str) or not session_ctx:
        raise PasskeyProtocolError("session/authorize did not return sessionCtxV2.")

    return SessionAuthorization(
        session_ctx_v2=session_ctx,
        require_ngc_mfa=bool(payload.get("requireNgcMfaForSecurityInfo")),
    )


def tap_pkce_login(
    *,
    session: requests.Session,
    authority: str,
    user_principal_name: str,
    tap: str,
    code_challenge: str,
    max_redirects: int = 15,
) -> str:
    state = new_state()
    auth_url = (
        f"https://login.microsoftonline.com/{authority}/oauth2/v2.0/authorize?"
        f"client_id={CLIENT_ID}"
        f"&redirect_uri={quoted(REDIRECT_URI)}"
        f"&scope={quoted(TOKEN_SCOPE)}"
        f"&response_type=code"
        f"&response_mode=fragment"
        f"&prompt=login"
        f"&login_hint={quoted(user_principal_name)}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&state={state}"
    )

    login_page = session.get(auth_url, allow_redirects=True, timeout=60)
    if login_page.status_code != HTTPStatus.OK:
        raise PasskeyProtocolError(f"Expected login page (200), got {login_page.status_code}.")

    config = parse_ests_config(login_page.text)
    if not config:
        raise PasskeyProtocolError("Could not extract $Config from login page.")
    if config.get("pgid") != "ConvergedSignIn":
        raise PasskeyProtocolError(
            f"Unexpected page: {config.get('pgid')}. Error: {config.get('strServiceExceptionMessage')}"
        )

    flow_token = str(config.get("sFT") or "")
    sctx = str(config.get("sCtx") or "")
    canary = str(config.get("canary") or "")
    api_canary = str(config.get("apiCanary") or "")
    session_id = str(config.get("sessionId") or "")
    url_post = str(config.get("urlPost") or "")

    try:
        gct_response = session.post(
            "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
            json={
                "username": user_principal_name,
                "isOtherIdpSupported": False,
                "checkPhones": False,
                "isRemoteNGCSupported": True,
                "isCookieBannerShown": False,
                "isFidoSupported": True,
                "originalRequest": sctx,
                "flowToken": flow_token,
            },
            headers={
                "canary": api_canary,
                "hpgrequestid": session_id,
                "hpgact": "1800",
                "hpgid": "1104",
            },
            timeout=60,
        )
        if gct_response.ok:
            flow_token = gct_response.json().get("FlowToken") or flow_token
    except requests.RequestException:
        pass

    current_url = url_post or "https://login.microsoftonline.com/common/login"
    current_url = resolve_absolute_url(auth_url, current_url)
    current_method = "POST"
    current_body = build_form_body(
        {
            "login": user_principal_name,
            "loginfmt": user_principal_name,
            "accesspass": tap,
            "ps": "56",
            "psRNGCDefaultType": "1",
            "psRNGCEntropy": "",
            "psRNGCSLK": flow_token,
            "canary": canary,
            "ctx": sctx,
            "hpgrequestid": session_id,
            "flowToken": flow_token,
            "PPSX": "",
            "NewUser": "1",
            "FoundMSAs": "",
            "fspost": "0",
            "i21": "0",
            "CookieDisclosure": "0",
            "IsFidoSupported": "1",
            "isSignupPost": "0",
            "DfpArtifact": "",
            "i19": "10000",
        }
    )

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

        if response.status_code == HTTPStatus.OK:
            form_action, form_payload = extract_hidden_form(response.text)
            if form_action and form_payload:
                current_url = resolve_absolute_url(current_url, form_action)
                current_method = "POST"
                current_body = build_form_body(form_payload)
                continue

            response_config = parse_ests_config(response.text)
            if response_config:
                error_message = response_config.get("strServiceExceptionMessage")
                if error_message:
                    raise PasskeyProtocolError(f"Login page error: {error_message}")
                if response_config.get("pgid") == "ConvergedSignIn":
                    raise PasskeyProtocolError("Returned to login page. The TAP may be invalid or expired.")

                url_post_value = str(response_config.get("urlPost") or "")
                page_id = str(response_config.get("pgid") or "")
                if "kmsi" in page_id.lower() or "kmsi" in url_post_value.lower():
                    kmsi_fields = {
                        "LoginOptions": "1",
                        "ctx": str(response_config.get("sCtx") or ""),
                        "flowToken": str(response_config.get("sFT") or ""),
                        "canary": str(response_config.get("canary") or ""),
                        "hpgrequestid": str(response_config.get("sessionId") or ""),
                    }
                    current_url = resolve_absolute_url(current_url, url_post_value or "/kmsi")
                    current_method = "POST"
                    current_body = build_form_body(kmsi_fields)
                    continue

                raise PasskeyProtocolError(
                    f"Unhandled ESTS interrupt page '{response_config.get('pgid')}' during login."
                )

            raise PasskeyProtocolError("Unexpected 200 response during TAP login.")

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                raise PasskeyProtocolError("Redirect response did not include a Location header.")
            location = resolve_absolute_url(current_url, location)
            auth_code, error = _extract_code_or_error(location)
            if auth_code:
                return auth_code
            if error:
                raise PasskeyProtocolError(f"Login failed: {error}")
            current_url = location
            current_method = "GET"
            current_body = ""
            continue

        raise PasskeyProtocolError(
            f"Unexpected TAP login response: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    raise PasskeyProtocolError(f"Failed to get auth code after {max_redirects} redirect steps.")


def silent_auth_with_ests_cookie(
    *,
    session: requests.Session,
    authority: str,
    ests_auth_cookie: str,
    code_challenge: str,
    max_redirects: int = 10,
) -> str:
    inject_ests_auth_cookie(session, ests_auth_cookie)

    state = new_state()
    current_url = (
        f"https://login.microsoftonline.com/{authority}/oauth2/v2.0/authorize?"
        f"client_id={CLIENT_ID}"
        f"&redirect_uri={quoted(REDIRECT_URI)}"
        f"&scope={quoted(TOKEN_SCOPE)}"
        f"&response_type=code"
        f"&response_mode=fragment"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&state={state}"
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

        if response.status_code == HTTPStatus.OK:
            form_action, form_payload = extract_hidden_form(response.text)
            if form_action and form_payload:
                current_url = resolve_absolute_url(current_url, form_action)
                current_method = "POST"
                current_body = build_form_body(form_payload)
                continue

            page_config = parse_ests_config(response.text)
            if page_config:
                page_id = str(page_config.get("pgid") or "")
                error_message = page_config.get("strServiceExceptionMessage")
                if page_id == "ConvergedTFA":
                    raise PasskeyProtocolError(
                        "MFA required but not satisfied. Capture the ESTSAUTH cookie after MFA completes."
                    )
                if page_id == "ConvergedSignIn":
                    raise PasskeyProtocolError("Cookie session expired or invalid.")
                if error_message:
                    raise PasskeyProtocolError(f"Azure AD returned page '{page_id}' with error: {error_message}")
                raise PasskeyProtocolError(
                    f"Azure AD returned page '{page_id}' instead of a silent auth redirect."
                )

            raise PasskeyProtocolError("Unexpected 200 response during silent auth.")

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                raise PasskeyProtocolError("Redirect response did not include a Location header.")
            location = resolve_absolute_url(current_url, location)
            auth_code, error = _extract_code_or_error(location)
            if auth_code:
                return auth_code
            if error:
                raise PasskeyProtocolError(f"Silent auth failed: {error}")
            current_url = location
            current_method = "GET"
            current_body = ""
            continue

        raise PasskeyProtocolError(
            f"Unexpected silent auth response: HTTP {response.status_code}. ResponseBody={response.text[:1000]}"
        )

    raise PasskeyProtocolError(f"Failed to get auth code via silent auth after {max_redirects} redirects.")
