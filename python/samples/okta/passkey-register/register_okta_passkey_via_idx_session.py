from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OKTA_ROOT = Path(__file__).resolve().parents[1]
if str(OKTA_ROOT) not in sys.path:
    sys.path.insert(0, str(OKTA_ROOT))

from okta_common import (  # noqa: E402
    USER_AGENT,
    b64url_decode,
    b64url_encode,
    create_key,
    get_key_vault_token,
    idx_post,
    normalize_origin,
    remediation,
    same_org_url,
)

try:
    import cbor2
except ImportError:  # pragma: no cover - reported when the script is actually run
    cbor2 = None


def import_cookies(session: requests.Session, value: str, origin: str) -> int:
    count = 0
    host = origin.removeprefix("https://")
    for item in value.split(";"):
        if "=" not in item:
            continue
        name, cookie_value = item.strip().split("=", 1)
        if name:
            session.cookies.set(name, cookie_value, domain=host, path="/")
            count += 1
    if not count:
        raise ValueError("Cookie header did not contain importable cookies.")
    return count


def key_name_for(user_name: str) -> str:
    safe = "".join(char for char in user_name if char.isalnum() or char == "-").lower()[:12] or "oktauser"
    return f"okta-pk-{safe}-{secrets.randbelow(900000) + 100000}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll an Okta WebAuthn credential using an active IDX browser session.")
    parser.add_argument("--okta-domain", required=True)
    parser.add_argument("--cookie-header", required=True)
    parser.add_argument("--state-handle", required=True)
    parser.add_argument("--authenticator-id", required=True)
    parser.add_argument("--keyvault-name", required=True)
    parser.add_argument("--keyvault-key-name")
    parser.add_argument("--keyvault-access-token")
    parser.add_argument("--output-path")
    parser.add_argument("--transport", choices=("usb", "internal"), default="usb")
    args = parser.parse_args()
    if cbor2 is None:
        raise RuntimeError("This registration sample requires cbor2; install the canonical Python library dependencies first.")
    origin = normalize_origin(args.okta_domain)
    host = origin.removeprefix("https://")
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    imported = import_cookies(session, args.cookie_header, origin)
    headers = {"Accept": "application/json", "Origin": origin, "Referer": f"{origin}/", "User-Agent": USER_AGENT}
    selected = idx_post(
        session,
        f"{origin}/idp/idx/credential/enroll",
        {"authenticator": {"id": args.authenticator_id}, "stateHandle": args.state_handle},
        headers,
    )
    activation = (((selected.get("currentAuthenticator") or {}).get("value") or {}).get("contextualData") or {}).get("activationData") or {}
    if not activation.get("challenge") or not activation.get("user") or not activation.get("pubKeyCredParams"):
        raise RuntimeError("Okta did not return WebAuthn activation data; the browser state may be expired.")
    algorithms = [item.get("alg") for item in activation["pubKeyCredParams"]]
    if -7 not in algorithms:
        raise RuntimeError(f"Okta did not offer ES256 (-7); offered algorithms: {algorithms}")
    finish = remediation(selected, "enroll-authenticator")
    if not finish:
        raise RuntimeError("Okta did not return the enroll-authenticator remediation.")
    rp_id = str((activation.get("rp") or {}).get("id") or host)
    token = get_key_vault_token(args.keyvault_access_token)
    key_name = args.keyvault_key_name or key_name_for(str((activation.get("user") or {}).get("name") or "user"))
    print(f"Creating Key Vault key '{key_name}'...", file=sys.stderr)
    key = create_key(session=session, key_vault_name=args.keyvault_name, key_name=key_name, access_token=token)
    credential_id_bytes = secrets.token_bytes(32)
    credential_id = b64url_encode(credential_id_bytes)
    public_x = b64url_decode(key["x"])
    public_y = b64url_decode(key["y"])
    cose_key = {1: 2, 3: -7, -1: 1, -2: public_x, -3: public_y}
    rp_hash = __import__("hashlib").sha256(rp_id.encode("utf-8")).digest()
    auth_data = rp_hash + bytes([0x45]) + bytes(4) + bytes(16) + len(credential_id_bytes).to_bytes(2, "big") + credential_id_bytes + cbor2.dumps(cose_key)
    client_data = json.dumps({"type": "webauthn.create", "challenge": activation["challenge"], "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode("utf-8")
    batch_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Key Vault Passkey POC")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(batch_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(batch_key, hashes.SHA256())
    )
    attestation_signature = batch_key.sign(auth_data + __import__("hashlib").sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    attestation = cbor2.dumps({"fmt": "packed", "attStmt": {"alg": -7, "sig": attestation_signature, "x5c": [certificate.public_bytes(serialization.Encoding.DER)]}, "authData": auth_data})
    completion = idx_post(
        session,
        same_org_url(finish["href"], origin),
        {"credentials": {"clientData": base64.b64encode(client_data).decode(), "attestation": base64.b64encode(attestation).decode(), "transports": json.dumps([args.transport], separators=(",", ":")), "clientExtensions": json.dumps({"credProps": {"rk": False}}, separators=(",", ":"))}, "stateHandle": selected.get("stateHandle")},
        headers,
    )
    if not completion.get("success"):
        raise RuntimeError("Okta did not return a success remediation; no credential record was written.")
    record = {
        "credentialId": credential_id,
        "relyingParty": rp_id,
        "url": origin,
        "userName": str((activation.get("user") or {}).get("name") or ""),
        "keyVault": {"vaultName": args.keyvault_name, "keyName": key_name, "keyId": key["kid"]},
        "okta": {"userId": str((activation.get("user") or {}).get("id") or ""), "transport": args.transport},
    }
    output = Path(args.output_path or f"okta-passkey-{key_name}.json")
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"✓ Okta accepted the registration; credential record: {output}", file=sys.stderr)
    print(json.dumps({**record, "importedCookieCount": imported}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
