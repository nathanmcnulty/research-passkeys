"""Single-tenant public-cloud Entra v2 delegated access-token boundary.

Only server configuration selects issuer, audience, clients, scope and JWKS URL.
A configured authentication-context claim does not establish device/ceremony proof.
"""
from dataclasses import dataclass
import base64
import json
import re
import threading
import time
from uuid import UUID

import jwt
import requests

from .coordination import AuthenticatedCaller
from .errors import ClaimsChallenge, InvalidRequest, Unauthenticated
from .storage import strict_json

BEARER = re.compile(r"(?i:Bearer) ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\Z")


def canonical_guid(value):
    try:
        if not isinstance(value, str):
            raise ValueError()
        return str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise InvalidRequest("A configured identity must be a UUID.") from exc


@dataclass(frozen=True)
class EntraConfig:
    tenant_id: str
    audience: str
    allowed_clients: frozenset[str]
    required_auth_context: str
    required_scope: str = "Passkey.Access"

    def __post_init__(self):
        object.__setattr__(self, "tenant_id", canonical_guid(self.tenant_id))
        object.__setattr__(self, "audience", canonical_guid(self.audience))
        if not isinstance(self.required_auth_context, str) or not re.fullmatch(r"c[1-9][0-9]?", self.required_auth_context):
            raise InvalidRequest("An explicit authentication context ID c1 through c99 is required.")
        if not isinstance(self.allowed_clients, (set, frozenset, tuple, list)) or not 1 <= len(self.allowed_clients) <= 32:
            raise InvalidRequest("An explicit bounded client allowlist is required.")
        clients = frozenset(canonical_guid(client) for client in self.allowed_clients)
        if not isinstance(self.required_scope, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", self.required_scope):
            raise InvalidRequest("Approved clients and an explicit delegated scope are required.")
        object.__setattr__(self, "allowed_clients", clients)

    @property
    def issuer(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"


class EntraTokenVerifier:
    def __init__(self, config: EntraConfig, *, jwks_loader=None, monotonic=time.monotonic):
        self.config = config
        self._loader = jwks_loader or self._load_jwks
        self._clock = monotonic
        self._lock = threading.Lock()
        self._keys = {}
        self._fetched_at = None
        self._last_attempt = None

    def _load_jwks(self):
        # No token-supplied URL, authorization header, redirect or discovery URL.
        with requests.Session() as session:
            session.trust_env = False  # No ambient proxy credentials or .netrc.
            with session.get(self.config.jwks_url, timeout=(5, 10), allow_redirects=False, stream=True,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"}) as response:
                if response.status_code != 200 or response.headers.get("Content-Encoding", "identity") not in ("", "identity"):
                    raise ValueError("Signing keys unavailable")
                data = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    data.extend(chunk)
                    if len(data) > 131072:
                        raise ValueError("Signing key response exceeds its budget")
                return strict_json(data.decode("utf-8"))

    def _key(self, kid):
        with self._lock:
            now = self._clock()
            if self._fetched_at is not None and now - self._fetched_at < 300 and kid in self._keys:
                return self._keys[kid]
            # Unknown kid floods cannot force a network request on every token.
            if self._last_attempt is not None and now - self._last_attempt < 30:
                raise ValueError("Signing key refresh is bounded")
            self._last_attempt = now
            document = self._loader()
            if not isinstance(document, dict) or not isinstance(document.get("keys"), list) or not 1 <= len(document["keys"]) <= 32:
                raise ValueError("Malformed signing keys")
            keys, seen = {}, set()
            for value in document["keys"]:
                if not isinstance(value, dict) or not isinstance(value.get("kid"), str) or not 1 <= len(value["kid"]) <= 256 or value["kid"] in seen:
                    raise ValueError("Ambiguous signing key identity")
                seen.add(value["kid"])
                if any(name in value for name in ("d", "p", "q", "dp", "dq", "qi")):
                    raise ValueError("Signing key must be public")
                if value.get("kty") != "RSA" or value.get("use", "sig") != "sig" or value.get("alg", "RS256") != "RS256":
                    continue
                if "key_ops" in value and value["key_ops"] != ["verify"]:
                    raise ValueError("Signing key operations are invalid")
                if "issuer" in value and value["issuer"].replace("{tenantid}", self.config.tenant_id) != self.config.issuer:
                    raise ValueError("Signing key issuer does not match")
                key = jwt.PyJWK.from_dict(value, algorithm="RS256").key
                if not 2048 <= key.key_size <= 8192:
                    raise ValueError("Signing key strength is invalid")
                keys[value["kid"]] = key
            if not keys:
                raise ValueError("No supported signing keys")
            self._keys, self._fetched_at = keys, self._clock()
            if kid not in keys:
                raise ValueError("Unknown signing key")
            return keys[kid]

    def verify(self, authorization: str) -> AuthenticatedCaller:
        try:
            if not isinstance(authorization, str) or len(authorization) > 16384:
                raise ValueError()
            match = BEARER.fullmatch(authorization)
            if not match:
                raise ValueError()
            token = match[1]
            segments = token.split(".")
            header = strict_json(jwt.utils.base64url_decode(segments[0]).decode("utf-8"))
            untrusted = strict_json(jwt.utils.base64url_decode(segments[1]).decode("utf-8"))
            if not isinstance(header, dict) or not isinstance(untrusted, dict):
                raise ValueError()
            if header.get("alg") != "RS256" or any(field in header for field in ("jku", "jwk", "x5u", "crit", "b64")):
                raise ValueError()
            if header.get("typ") not in (None, "JWT", "at+jwt"):
                raise ValueError()
            kid = header.get("kid")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 256:
                raise ValueError()
            # Unverified claims can reject a token early; they never authorize it.
            if untrusted.get("iss") != self.config.issuer or untrusted.get("aud") != self.config.audience:
                raise ValueError()
            claims = jwt.decode(token, self._key(kid), algorithms=["RS256"], audience=self.config.audience,
                issuer=self.config.issuer, leeway=0, options={"strict_aud": True,
                    "require": ["iss", "aud", "exp", "iat", "nbf", "sub", "tid", "oid", "azp", "ver", "scp"]})
            if (claims["ver"] != "2.0" or canonical_guid(claims["tid"]) != self.config.tenant_id or
                    claims.get("idtyp") not in (None, "user") or "cnf" in claims or
                    not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 256):
                raise ValueError()
            if any(type(claims[name]) is not int for name in ("exp", "iat", "nbf")) or claims["exp"] <= max(claims["iat"], claims["nbf"]):
                raise ValueError()
            scopes = claims["scp"]
            if not isinstance(scopes, str) or len(scopes) > 2048 or not re.fullmatch(r"[\x21-\x7e]+(?: [\x21-\x7e]+)*", scopes):
                raise ValueError()
            client = canonical_guid(claims["azp"])
            object_id = canonical_guid(claims["oid"])
            if client not in self.config.allowed_clients or self.config.required_scope not in scopes.split(" "):
                raise ValueError()
            contexts = claims.get("acrs", [])
            if not isinstance(contexts, list) or len(contexts) > 99 or any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in contexts):
                raise ValueError()
            if self.config.required_auth_context not in contexts:
                requested = {"access_token": {"acrs": {"essential": True, "value": self.config.required_auth_context}}}
                encoded = base64.b64encode(json.dumps(requested, separators=(",", ":")).encode()).decode("ascii")
                header = (f'Bearer realm="{self.config.tenant_id}", '
                    f'authorization_uri="https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/authorize", '
                    f'error="insufficient_claims", claims="{encoded}", cc_type="authcontext"')
                raise ClaimsChallenge(header)
            return AuthenticatedCaller(self.config.tenant_id, object_id, client, claims["exp"])
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, RecursionError, InvalidRequest, requests.RequestException) as exc:
            raise Unauthenticated("Fresh broker authentication is required.") from exc
