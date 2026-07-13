from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests

OKTA_ROOT = Path(__file__).resolve().parents[0]
if str(OKTA_ROOT) not in sys.path:
    sys.path.insert(0, str(OKTA_ROOT))

from okta_common import b64url_encode, normalize_origin  # noqa: E402


REQUIRED_SCOPE = "okta.myAccount.webauthn.manage"


class CallbackHandler(BaseHTTPRequestHandler):
    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        CallbackHandler.result = {key: values[0] for key, values in parse_qs(urlparse(self.path).query).items()}
        body = b"<title>Okta authorization complete</title><p>You can close this window.</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def acquire_token(origin: str, client_id: str, redirect_uri: str, timeout: int) -> str:
    parsed = urlparse(redirect_uri)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.scheme != "http":
        raise ValueError("redirect URI must be an HTTP loopback URI")
    verifier = b64url_encode(secrets.token_bytes(32))
    challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    state = b64url_encode(secrets.token_bytes(24))
    authorize = f"{origin}/oauth2/v1/authorize?{urlencode({
        'client_id': client_id,
        'response_type': 'code',
        'response_mode': 'query',
        'redirect_uri': redirect_uri,
        'scope': f'openid profile {REQUIRED_SCOPE}',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    })}"
    CallbackHandler.result = {}
    server = HTTPServer((parsed.hostname or "127.0.0.1", parsed.port or 8765), CallbackHandler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    print("Open this URL and complete Okta sign-in:", file=sys.stderr)
    print(authorize, file=sys.stderr)
    webbrowser.open(authorize)
    thread.join(timeout)
    server.server_close()
    if not CallbackHandler.result:
        raise TimeoutError("Timed out waiting for the OAuth redirect.")
    result = CallbackHandler.result
    if result.get("error"):
        raise RuntimeError(f"Okta authorization failed: {result['error']} {result.get('error_description', '')}")
    if result.get("state") != state or not result.get("code"):
        raise RuntimeError("OAuth state validation failed or Okta returned no authorization code.")
    token = requests.post(
        f"{origin}/oauth2/v1/token",
        data={"grant_type": "authorization_code", "client_id": client_id, "code": result["code"], "redirect_uri": redirect_uri, "code_verifier": verifier},
        timeout=60,
    )
    if not token.ok:
        raise RuntimeError(f"Token exchange failed: HTTP {token.status_code}: {token.text[:1000]}")
    return str(token.json()["access_token"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Start an Okta MyAccount WebAuthn registration ceremony.")
    parser.add_argument("--okta-domain", required=True)
    parser.add_argument("--client-id")
    parser.add_argument("--redirect-uri", default="http://127.0.0.1:8765/callback/")
    parser.add_argument("--access-token")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    origin = normalize_origin(args.okta_domain)
    access_token = args.access_token or os.getenv("OKTA_ACCESS_TOKEN")
    if not access_token:
        if not args.client_id:
            parser.error("--client-id is required unless --access-token or OKTA_ACCESS_TOKEN is supplied")
        access_token = acquire_token(origin, args.client_id, args.redirect_uri, args.timeout_seconds)

    response = requests.post(
        f"{origin}/idp/myaccount/webauthn/registration",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json; okta-version=1.0.0", "Content-Type": "application/json"},
        timeout=60,
    )
    if not response.ok:
        raise RuntimeError(f"Okta registration-start call failed: HTTP {response.status_code}: {response.text[:1000]}")
    registration = response.json()
    options = registration.get("options") or {}
    if not options.get("challenge") or not registration.get("expiresAt"):
        raise RuntimeError("Okta returned an unexpected registration-start response.")
    print(json.dumps({
        "success": True,
        "origin": origin,
        "expiresAt": registration.get("expiresAt"),
        "challenge": options.get("challenge"),
        "pubKeyCredParams": options.get("pubKeyCredParams"),
        "authenticatorSelection": options.get("authenticatorSelection"),
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, TimeoutError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
