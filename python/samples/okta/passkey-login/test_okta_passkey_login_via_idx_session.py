from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

OKTA_ROOT = Path(__file__).resolve().parents[1]
if str(OKTA_ROOT) not in sys.path:
    sys.path.insert(0, str(OKTA_ROOT))

from okta_common import (  # noqa: E402
    USER_AGENT,
    credential_values,
    get_key_vault_token,
    load_record,
    normalize_origin,
    sign_digest,
)


def import_cookie_header(session: requests.Session, cookie_header: str, origin: str) -> int:
    count = 0
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        name, value = item.strip().split("=", 1)
        if name:
            session.cookies.set(name, value, domain=urlparse(origin).hostname, path="/")
            count += 1
    if not count:
        raise ValueError("Cookie header did not contain importable cookies.")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit a Key Vault-backed assertion to an active Okta IDX session.")
    parser.add_argument("--okta-domain", required=True)
    parser.add_argument("--cookie-header", help="Browser Cookie header; omitted only when --prompt-cookie is used.")
    parser.add_argument("--prompt-cookie", action="store_true")
    parser.add_argument("--state-handle", required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--credential-path")
    parser.add_argument("--credential-id")
    parser.add_argument("--keyvault-name")
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-key-id")
    parser.add_argument("--relying-party")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--sign-count", type=int, default=0)
    args = parser.parse_args()
    if args.sign_count < 0 or args.sign_count > 2**32 - 1:
        parser.error("--sign-count must be between 0 and 4294967295")
    if not args.challenge.replace("-", "").replace("_", "").isalnum():
        parser.error("--challenge must be Okta's base64url challenge")

    origin = normalize_origin(args.okta_domain)
    host = urlparse(origin).hostname or ""
    cookie_header = args.cookie_header or (getpass.getpass("Copy the browser Cookie header: ") if args.prompt_cookie else None)
    if not cookie_header:
        parser.error("--cookie-header or --prompt-cookie is required")
    state_handle = args.state_handle if args.state_handle else getpass.getpass("IDX stateHandle: ")
    record = load_record(args.credential_path) if args.credential_path else None
    credential = credential_values(
        record,
        credential_id=args.credential_id,
        key_vault_name=args.keyvault_name,
        key_name=args.keyvault_key_name,
        key_id=args.keyvault_key_id,
        relying_party=args.relying_party,
    )
    relying_party = credential[4] or host

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    imported = import_cookie_header(session, cookie_header, origin)
    headers = {
        "Accept": "application/json",
        "Origin": origin,
        "Referer": f"{origin}/",
        "User-Agent": USER_AGENT,
    }
    rp_hash = hashlib.sha256(relying_party.encode("utf-8")).digest()
    auth_data = rp_hash + bytes([0x05]) + args.sign_count.to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": args.challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    print("Signing the Okta assertion with Azure Key Vault...", file=sys.stderr)
    signature = sign_digest(
        session=session,
        key_vault_name=credential[1],
        key_name=credential[2],
        key_id=credential[3],
        digest=digest,
        access_token=get_key_vault_token(args.keyvault_access_token),
    )
    response = session.post(
        f"{origin}/idp/idx/challenge/answer",
        headers=headers,
        json={
            "credentials": {
                "clientData": base64.b64encode(client_data).decode("ascii"),
                "authenticatorData": base64.b64encode(auth_data).decode("ascii"),
                "signatureData": base64.b64encode(signature).decode("ascii"),
            },
            "stateHandle": state_handle,
        },
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f"Okta assertion request failed: HTTP {response.status_code}: {response.text[:1000]}")
    payload = response.json()
    if not payload.get("success"):
        messages = "; ".join(str(item.get("message")) for item in ((payload.get("messages") or {}).get("value") or []))
        raise RuntimeError(f"Okta rejected the passkey assertion: {messages or 'no success remediation'}")
    print("✓ Okta accepted the Key Vault-backed passkey assertion.", file=sys.stderr)
    print(json.dumps({
        "success": True,
        "credentialId": credential[0],
        "userName": (record or {}).get("userName"),
        "successStep": (payload.get("success") or {}).get("name"),
        "importedCookieCount": imported,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
