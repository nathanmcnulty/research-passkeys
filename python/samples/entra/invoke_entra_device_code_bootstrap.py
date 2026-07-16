from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import msal

DEFAULT_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEFAULT_TENANT_ID = "replace-with-your-tenant-id"
DEFAULT_SCOPE = ["https://graph.microsoft.com/.default"]


def decode_jwt_payload(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Token does not contain a JWT payload.")
    payload = parts[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Acquire a delegated token with device code flow.")
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--scope", action="append", dest="scopes")
    args = parser.parse_args()

    scopes = args.scopes or DEFAULT_SCOPE
    authority = f"https://login.microsoftonline.com/{args.tenant_id}"
    app = msal.PublicClientApplication(args.client_id, authority=authority)

    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        raise ValueError(f"Failed to create device flow: {json.dumps(flow, indent=2)}")

    print(flow["message"])
    sys.stdout.flush()
    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": result.get("error"),
                    "error_description": result.get("error_description"),
                    "correlation_id": result.get("correlation_id"),
                },
                separators=(",", ":"),
            )
        )
        return 1

    claims = decode_jwt_payload(result["access_token"])
    print(
        json.dumps(
            {
                "success": True,
                "tenantId": claims.get("tid"),
                "userPrincipalName": claims.get("preferred_username") or claims.get("upn"),
                "scopes": result.get("scope"),
                "expiresIn": result.get("expires_in"),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
