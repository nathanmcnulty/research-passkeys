import copy
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from kvpp_broker.auth import EntraConfig, EntraTokenVerifier
from test_coordination import TENANT, OWNER, APP

AUDIENCE = "55555555-5555-4555-8555-555555555555"
CONFIG = EntraConfig(TENANT, AUDIENCE, frozenset([APP]), required_auth_context="c1")
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(private=PRIVATE, kid="fixture-one"):
    return {**jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True),
        "kid": kid, "use": "sig", "alg": "RS256", "issuer": CONFIG.issuer}


def payload(**overrides):
    now = int(time.time())
    return {"iss": CONFIG.issuer, "aud": AUDIENCE, "exp": now + 600, "iat": now - 1, "nbf": now - 1,
        "sub": "synthetic-subject", "tid": TENANT, "oid": OWNER, "azp": APP,
        "ver": "2.0", "scp": "Passkey.Access", "acrs": ["c1"], **overrides}


def token(claims=None, headers=None, private=PRIVATE):
    return jwt.encode(claims or payload(), private, algorithm="RS256", headers={"kid": "fixture-one", **(headers or {})})


def manual_token(header, body, private=PRIVATE):
    # Used to sign otherwise ambiguous JSON exactly, without library normalization.
    header_bytes = header if isinstance(header, bytes) else header.encode() if isinstance(header, str) else json.dumps(header).encode()
    body_bytes = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else json.dumps(body).encode()
    message = jwt.utils.base64url_encode(header_bytes) + b"." + jwt.utils.base64url_encode(body_bytes)
    signature = private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + jwt.utils.base64url_encode(signature)).decode("ascii")


def verifier(document=None):
    keys = document if document is not None else {"keys": [jwk()]}
    return EntraTokenVerifier(CONFIG, jwks_loader=lambda: copy.deepcopy(keys))
