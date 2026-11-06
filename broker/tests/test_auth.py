import concurrent.futures
import copy
import json
import time
import unittest
from unittest.mock import patch

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

from kvpp_broker.auth import EntraConfig, EntraTokenVerifier
from kvpp_broker.errors import ClaimsChallenge, InvalidRequest, Unauthenticated
from auth_fixtures import CONFIG, PRIVATE, OTHER_PRIVATE, jwk, manual_token, payload, token, verifier
from test_coordination import TENANT, OWNER, APP, OTHER_OWNER


class EntraTokenVerificationTests(unittest.TestCase):
    def test_signed_delegated_access_token_derives_immutable_identity(self):
        caller = verifier().verify("Bearer " + token(payload(preferred_username="untrusted-display", owner=OTHER_OWNER)))
        self.assertEqual((caller.tenant_id, caller.object_id, caller.application_id), (TENANT, OWNER, APP))

    def test_wrong_issuer_or_audience_is_denied_before_key_fetch(self):
        def unexpected_fetch():
            self.fail("Wrong resource/issuer must not cause metadata network access")
        api = EntraTokenVerifier(CONFIG, jwks_loader=unexpected_fetch)
        for overrides in [{"iss": CONFIG.issuer + "/"}, {"iss": "https://attacker.invalid/issuer"},
                {"aud": APP}, {"aud": [CONFIG.audience]}, {"aud": "https://vault.azure.net"}]:
            with self.subTest(overrides=overrides), self.assertRaises(Unauthenticated):
                api.verify("Bearer " + token(payload(**overrides)))

    def test_wrong_tenant_owner_client_and_delegation_claims_fail(self):
        for overrides in [{"tid": OTHER_OWNER}, {"oid": "not-an-object-id"}, {"azp": OTHER_OWNER},
                {"azp": True}, {"scp": "Passkey.Access.Other"}, {"scp": ["Passkey.Access"]},
                {"scp": "Passkey.Access\nOther"}, {"idtyp": "app"}, {"ver": "1.0"}, {"sub": 1}]:
            with self.subTest(overrides=overrides), self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + token(payload(**overrides)))

    def test_required_claims_cannot_be_substituted_by_roles_or_client_booleans(self):
        for name in ["exp", "iat", "nbf", "sub", "tid", "oid", "azp", "scp", "ver"]:
            claims = payload(roles=["Passkey.Access"], userVerified=True, pinVerified=True)
            claims.pop(name)
            with self.subTest(name=name), self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + token(claims))

    def test_expiration_future_dates_and_non_integer_dates_fail(self):
        now = int(time.time())
        for overrides in [{"exp": now - 1}, {"iat": now + 100}, {"nbf": now + 100},
                {"exp": str(now + 100)}, {"iat": now - 0.5}, {"nbf": True}]:
            with self.subTest(overrides=overrides), self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + token(payload(**overrides)))

    def test_forged_signature_and_symmetric_algorithm_confusion_fail(self):
        values = [token(private=OTHER_PRIVATE), jwt.encode(payload(), "synthetic-symmetric-secret-long-enough", algorithm="HS256", headers={"kid": "fixture-one"})]
        for value in values:
            with self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + value)

    def test_sender_constrained_tokens_cannot_be_downgraded_to_bearer(self):
        for claims in [payload(cnf={"kid": "bound-key"}), payload(cnf={"jkt": "bound-thumbprint"}), payload(idtyp="agent")]:
            with self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + token(claims))
        with self.assertRaises(Unauthenticated):
            verifier().verify("Bearer " + token(headers={"typ": "dpop+jwt"}))

    def test_token_cannot_select_remote_keys_or_critical_headers(self):
        def unexpected_fetch():
            self.fail("Token-controlled metadata must never be fetched")
        api = EntraTokenVerifier(CONFIG, jwks_loader=unexpected_fetch)
        for headers in [{"jku": "https://attacker.invalid/keys"}, {"jwk": jwk(OTHER_PRIVATE)},
                {"x5u": "https://attacker.invalid/certificate"}, {"crit": ["unknown"]}, {"b64": False}]:
            with self.subTest(headers=list(headers)), self.assertRaises(Unauthenticated):
                api.verify("Bearer " + manual_token({"alg": "RS256", "kid": "fixture-one", **headers}, payload()))

    def test_duplicate_json_fields_are_rejected_even_when_signed(self):
        body = json.dumps(payload())[:-1] + ',"oid":"' + OTHER_OWNER + '"}'
        values = [manual_token({"alg": "RS256", "kid": "fixture-one"}, body),
            manual_token('{"alg":"RS256","kid":"other","kid":"fixture-one"}', payload())]
        for value in values:
            with self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + value)

    def test_non_utf8_or_over_nested_signed_json_fails_as_authentication(self):
        header = {"alg": "RS256", "kid": "fixture-one"}
        values = [manual_token(header, json.dumps(payload()).encode("utf-16")),
            manual_token(json.dumps(header).encode("utf-16"), payload()),
            manual_token(header, '{"noise":' + "[" * 1100 + "0" + "]" * 1100 + "}")]
        for value in values:
            with self.assertRaises(Unauthenticated):
                verifier().verify("Bearer " + value)

    def test_malformed_oversized_and_merged_bearer_headers_fail(self):
        good = "Bearer " + token()
        for value in ["", "Basic abc", good + ", " + good, good + " ", "Bearer abc.def.ghi", "Bearer " + "a" * 16384]:
            with self.assertRaises(Unauthenticated):
                verifier().verify(value)

    def test_ambiguous_private_wrong_issuer_and_weak_jwks_fail(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        documents = [{"keys": [jwk(), jwk(OTHER_PRIVATE)]}, {"keys": [{**jwk(), "d": "private"}]},
            {"keys": [{**jwk(), "issuer": CONFIG.issuer.replace(TENANT, OTHER_OWNER)}]},
            {"keys": [{**jwk(), "key_ops": ["sign"]}]}, {"keys": [jwk(weak)]},
            {"keys": []}, {"keys": [jwk()] * 33}, {"keys": [{**jwk(), "alg": "HS256"}]}]
        for document in documents:
            private = weak if document == {"keys": [jwk(weak)]} else PRIVATE
            with self.subTest(document_keys=len(document["keys"])), self.assertRaises(Unauthenticated):
                verifier(document).verify("Bearer " + manual_token({"alg": "RS256", "kid": "fixture-one"}, payload(), private))

    def test_unknown_key_refresh_is_bounded_and_rotation_is_supported(self):
        now, calls = [0], []
        keys = [{"keys": [jwk()]}]
        def load():
            calls.append(True)
            return copy.deepcopy(keys[0])
        api = EntraTokenVerifier(CONFIG, jwks_loader=load, monotonic=lambda: now[0])
        api.verify("Bearer " + token())
        rotated = token(headers={"kid": "fixture-two"}, private=OTHER_PRIVATE)
        for _ in range(3):
            with self.assertRaises(Unauthenticated):
                api.verify("Bearer " + rotated)
        self.assertEqual(len(calls), 1)
        now[0] = 31
        keys[0] = {"keys": [jwk(OTHER_PRIVATE, "fixture-two")]}
        self.assertEqual(api.verify("Bearer " + rotated).object_id, OWNER)
        self.assertEqual(len(calls), 2)

    def test_parallel_verification_fetches_keys_once(self):
        calls = []
        def load():
            calls.append(True)
            time.sleep(0.02)
            return {"keys": [jwk()]}
        api = EntraTokenVerifier(CONFIG, jwks_loader=load)
        value = "Bearer " + token()
        with concurrent.futures.ThreadPoolExecutor(8) as workers:
            results = list(workers.map(api.verify, [value] * 8))
        self.assertTrue(all(result.object_id == OWNER for result in results))
        self.assertEqual(len(calls), 1)

    def test_expired_key_cache_fails_closed_on_metadata_outage(self):
        now = [0]
        def load():
            if now[0]:
                raise requests.ConnectionError("synthetic outage")
            return {"keys": [jwk()]}
        api = EntraTokenVerifier(CONFIG, jwks_loader=load, monotonic=lambda: now[0])
        api.verify("Bearer " + token())
        now[0] = 301
        with self.assertRaises(Unauthenticated):
            api.verify("Bearer " + token())

    def test_default_loader_uses_only_configured_https_url_without_redirects(self):
        class Response:
            status_code = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def iter_content(self, **kwargs): yield json.dumps({"keys": [jwk()]}).encode()
        with patch("kvpp_broker.auth.requests.Session.get", autospec=True, return_value=Response()) as request:
            EntraTokenVerifier(CONFIG).verify("Bearer " + token())
        self.assertFalse(request.call_args.args[0].trust_env)
        self.assertEqual(request.call_args.args[1:], (CONFIG.jwks_url,))
        self.assertFalse(request.call_args.kwargs["allow_redirects"])
        self.assertEqual(request.call_args.kwargs["timeout"], (5, 10))
        self.assertNotIn("Authorization", request.call_args.kwargs["headers"])

    def test_metadata_redirect_compression_and_size_fail_closed(self):
        for status, headers, body in [(302, {}, b"{}"), (200, {"Content-Encoding": "gzip"}, b"{}"),
                (200, {}, b"a" * 131073), (200, {}, b"\xff")]:
            class Response:
                status_code = status
                def __enter__(self): return self
                def __exit__(self, *args): return None
                def iter_content(self, **kwargs): yield body
            response = Response()
            response.headers = headers
            with patch("kvpp_broker.auth.requests.Session.get", return_value=response), self.assertRaises(Unauthenticated):
                EntraTokenVerifier(CONFIG).verify("Bearer " + token())

    def test_invalid_server_policy_fails_during_configuration(self):
        for clients, scope in [(frozenset(), "Passkey.Access"), (None, "Passkey.Access"),
                (frozenset([APP]), None), (frozenset([APP]), "scope with spaces")]:
            with self.assertRaises(InvalidRequest):
                EntraConfig(TENANT, CONFIG.audience, clients, required_auth_context="c1", required_scope=scope)
        for context in [None, "", "c0", "c100", "unconfigured-policy"]:
            with self.assertRaises(InvalidRequest):
                EntraConfig(TENANT, CONFIG.audience, frozenset([APP]), required_auth_context=context)

    def test_missing_auth_context_requires_step_up_without_trusting_mfa_or_capability(self):
        for claims in [payload(acrs=[]), payload(acrs=["c2"]), payload(acrs=[], amr=["mfa"], xms_cc=["cp1"])]:
            with self.assertRaises(ClaimsChallenge):
                verifier().verify("Bearer " + token(claims))
        with self.assertRaises(Unauthenticated):
            verifier().verify("Bearer " + token(payload(acrs="c1")))


if __name__ == "__main__":
    unittest.main()
