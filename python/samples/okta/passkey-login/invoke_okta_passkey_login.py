from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode

import requests

OKTA_ROOT = Path(__file__).resolve().parents[1]
if str(OKTA_ROOT) not in sys.path:
    sys.path.insert(0, str(OKTA_ROOT))

from okta_common import (  # noqa: E402
    DEFAULT_CLIENT_ID,
    DEFAULT_SCOPE,
    USER_AGENT,
    b64url_encode,
    build_assertion,
    credential_values,
    get_key_vault_token,
    idx_post,
    load_record,
    normalize_origin,
    remediation,
    same_org_url,
    webauthn_id,
)


def decode_state_token(value: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticate to Okta with a Key Vault-backed passkey.")
    parser.add_argument("--okta-domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--credential-path")
    parser.add_argument("--credential-id")
    parser.add_argument("--keyvault-name")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-key-id")
    parser.add_argument("--relying-party")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--password", action="store_true", help="Prompt for the Okta password when policy requires it.")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--redirect-uri")
    parser.add_argument("--sign-count", type=int, default=1)
    args = parser.parse_args()
    if args.sign_count < 1 or args.sign_count > 2**32 - 1:
        parser.error("--sign-count must be between 1 and 4294967295")

    origin = normalize_origin(args.okta_domain)
    okta_host = origin.removeprefix("https://")
    record = load_record(args.credential_path) if args.credential_path else None
    credential = credential_values(
        record,
        credential_id=args.credential_id,
        key_vault_name=args.keyvault_name,
        key_name=args.keyvault_key_name,
        key_id=args.keyvault_key_id,
        relying_party=args.relying_party,
    )
    relying_party = credential[4] or okta_host
    redirect_uri = args.redirect_uri or f"{origin}/account-settings/callback"
    if not redirect_uri.startswith(origin + "/"):
        raise ValueError("redirect URI must use the Okta HTTPS origin")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Origin": origin,
        "Referer": f"{origin}/",
        "User-Agent": USER_AGENT,
    }
    verifier = b64url_encode(secrets.token_bytes(32))
    challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    oauth_state = b64url_encode(secrets.token_bytes(24))
    nonce = b64url_encode(secrets.token_bytes(24))
    authorize_uri = f"{origin}/oauth2/v1/authorize?{urlencode({
        'client_id': args.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'response_mode': 'query',
        'scope': DEFAULT_SCOPE,
        'state': oauth_state,
        'nonce': nonce,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    })}"

    print("Starting Okta login transaction...", file=sys.stderr)
    page = session.get(authorize_uri, headers=headers, timeout=60)
    page.raise_for_status()
    match = re.search(r"var\s+stateToken\s*=\s*'([^']+)'", page.text)
    if not match:
        raise RuntimeError("Could not extract Okta stateToken from the authorization page.")
    state_token = decode_state_token(match.group(1))
    idx_headers = {
        "Accept": "application/ion+json; okta-version=1.0.0",
        "Origin": origin,
        "Referer": authorize_uri,
        "User-Agent": USER_AGENT,
    }
    introspect = idx_post(session, f"{origin}/idp/idx/introspect", {"stateToken": state_token}, idx_headers)
    identify = remediation(introspect, "identify")
    if not identify:
        raise RuntimeError("Okta did not return the identify remediation.")
    identified = idx_post(
        session,
        same_org_url(identify["href"], origin),
        {"identifier": args.username, "stateHandle": introspect.get("stateHandle")},
        idx_headers,
    )
    passkey_id = webauthn_id(identified)
    if not passkey_id:
        raise RuntimeError("Okta did not report an enrolled webauthn authenticator for this user.")

    current = identified
    password = getpass.getpass("Okta password: ") if args.password else None
    if password:
        password_remediation = remediation(current, "challenge-authenticator")
        if password_remediation:
            current = idx_post(
                session,
                same_org_url(password_remediation["href"], origin),
                {"credentials": {"passcode": password}, "stateHandle": current.get("stateHandle")},
                idx_headers,
            )
            passkey_id = webauthn_id(current) or passkey_id

    select = remediation(current, "select-authenticator-authenticate")
    if not select:
        raise RuntimeError("Okta did not offer authenticator selection; use --password if required by policy.")
    selected = idx_post(
        session,
        same_org_url(select["href"], origin),
        {"authenticator": {"id": passkey_id}, "stateHandle": current.get("stateHandle")},
        idx_headers,
    )
    challenge_data = (((selected.get("currentAuthenticator") or {}).get("value") or {}).get("contextualData") or {}).get("challengeData") or {}
    if not challenge_data.get("challenge"):
        raise RuntimeError("Okta did not return a WebAuthn challenge.")

    access_token = get_key_vault_token(args.keyvault_access_token)
    print("Signing WebAuthn assertion with Azure Key Vault...", file=sys.stderr)
    assertion, _ = build_assertion(
        challenge=str(challenge_data["challenge"]),
        origin=origin,
        relying_party=relying_party,
        sign_count=args.sign_count,
        key_values=credential,
        session=session,
        access_token=access_token,
    )
    answer = remediation(selected, "challenge-authenticator")
    if not answer:
        raise RuntimeError("Okta did not return the WebAuthn challenge-answer remediation.")
    success = idx_post(
        session,
        same_org_url(answer["href"], origin),
        {"credentials": assertion, "stateHandle": selected.get("stateHandle")},
        idx_headers,
    )
    if not success.get("success"):
        messages = "; ".join(str(item.get("message")) for item in ((success.get("messages") or {}).get("value") or []))
        remaining = ", ".join(str(item.get("name")) for item in ((success.get("remediation") or {}).get("value") or []))
        raise RuntimeError(messages or f"Okta did not complete login. Remaining remediation(s): {remaining}")

    first_hop = session.get(same_org_url(success["success"]["href"], origin), headers=headers, allow_redirects=False, timeout=60)
    print("✓ Okta accepted the Key Vault-backed passkey assertion.", file=sys.stderr)
    print(f"  Success redirect status: {first_hop.status_code}", file=sys.stderr)
    print(json.dumps({
        "success": True,
        "userName": args.username,
        "credentialId": credential[0],
        "successRedirected": bool(first_hop.headers.get("Location")),
        "redirectStatus": first_hop.status_code,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
