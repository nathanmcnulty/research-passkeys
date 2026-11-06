from io import BytesIO
import base64
import json
import re
import unittest

from kvpp_broker.api import BrokerApplication
from kvpp_broker.coordination import Coordinator, Transaction
from kvpp_broker.errors import StorageUnavailable
from kvpp_broker.storage import MemoryStore
from auth_fixtures import payload, token, verifier
from test_coordination import APP, CREDENTIAL, OTHER_OWNER, caller, seed_active


def call(app, method, path, body=None, authorization=None, request_key="1" * 32, overrides=None):
    data = json.dumps(body).encode() if body is not None else b"{}"
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "HTTP_AUTHORIZATION": authorization or "Bearer " + token(),
        "HTTP_IDEMPOTENCY_KEY": request_key, "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(data)), "wsgi.input": BytesIO(data), **(overrides or {})}
    captured = {}
    def start(status, headers):
        captured.update(status=int(status.split()[0]), headers=dict(headers))
    raw = b"".join(app(environ, start))
    return captured["status"], json.loads(raw), captured["headers"]


class BrokerApiTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.coordinator = Coordinator(self.store, frozenset([APP]))
        self.app = BrokerApplication(self.coordinator, verifier())

    def test_authenticated_reservation_replay_read_and_abort(self):
        status, first, _ = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})
        self.assertEqual(status, 201)
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})[:2], (201, first))
        path = "/v1/credentials/" + first["credentialId"]
        self.assertEqual(call(self.app, "GET", path)[0], 200)
        self.assertEqual(call(self.app, "POST", "/v1/reservations/" + first["credentialId"] + "/abort", {}, request_key="2" * 32)[0], 200)
        self.assertEqual(call(self.app, "GET", path)[1]["state"], "aborted")
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})[1], first)
        self.assertEqual(call(self.app, "GET", path)[1]["state"], "aborted", "historical replay must not reactivate a reservation")

    def test_wrong_owner_and_unknown_resource_have_identical_denials(self):
        seed_active(self.store, caller())
        other = "Bearer " + token(payload(oid=OTHER_OWNER))
        first = call(self.app, "GET", "/v1/credentials/" + CREDENTIAL, authorization=other)
        second = call(self.app, "GET", "/v1/credentials/" + "f" * 32, authorization=other)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 404)

    def test_only_bearer_authentication_is_used(self):
        status, result, headers = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"},
            overrides={"HTTP_AUTHORIZATION": "", "HTTP_X_MS_CLIENT_PRINCIPAL": "forged-owner", "HTTP_COOKIE": "access_token=forged"})
        self.assertEqual(status, 401)
        self.assertIn("WWW-Authenticate", headers)
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_body_cannot_supply_owner_or_presence_authority(self):
        for extra in [{"owner": OTHER_OWNER}, {"tenantId": OTHER_OWNER}, {"userVerified": True}, {"pinVerified": True}, {"keyId": "private-key"}]:
            status, _, _ = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test", **extra})
            self.assertEqual(status, 400)
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_signed_mfa_or_client_booleans_do_not_open_protected_routes(self):
        authorization = "Bearer " + token(payload(amr=["mfa"], userVerified=True))
        routes = [("DELETE", f"/v1/credentials/{CREDENTIAL}"), ("POST", f"/v1/credentials/{CREDENTIAL}/sign"),
            ("POST", f"/v1/reservations/{CREDENTIAL}/finalize")]
        for method, path in routes:
            status, result, _ = call(self.app, method, path, {"userVerified": True, "pinVerified": True}, authorization)
            self.assertEqual(status, 501)
            self.assertEqual(result["error"]["code"], "proof_integration_required")
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_worker_claims_and_tickets_have_no_public_route(self):
        for path in [f"/v1/cleanup/{CREDENTIAL}/claim", f"/v1/cleanup/{CREDENTIAL}/begin", f"/v1/cleanup/{CREDENTIAL}/complete"]:
            self.assertEqual(call(self.app, "POST", path, {})[0], 404)
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_auth_context_challenge_is_server_bound_and_precedes_storage(self):
        authorization = "Bearer " + token(payload(acrs=[], amr=["mfa"], xms_cc=["cp1"]))
        status, result, headers = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"}, authorization)
        self.assertEqual(status, 401)
        self.assertEqual(result["error"]["code"], "insufficient_claims")
        header = headers["WWW-Authenticate"]
        self.assertIn('error="insufficient_claims"', header)
        encoded = re.search(r'claims="([^"]+)"', header).group(1)
        self.assertEqual(json.loads(base64.b64decode(encoded)), {"access_token": {"acrs": {"essential": True, "value": "c1"}}})
        self.assertIn("login.microsoftonline.com", header)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_cached_request_result_still_requires_current_auth_context(self):
        first = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})
        self.assertEqual(first[0], 201)
        status, result, _ = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"},
            "Bearer " + token(payload(acrs=[])))
        self.assertEqual(status, 401)
        self.assertEqual(result["error"]["code"], "insufficient_claims")
        self.assertNotIn("credentialId", result)
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})[:2], first[:2])
        self.assertEqual(self.store.read(caller().partition, "owner").value["revision"], 1)

    def test_request_conflict_and_private_coordinate_projection(self):
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})[0], 201)
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "other.test"})[0], 409)
        seed_active(self.store, caller())
        status, result, _ = call(self.app, "GET", f"/v1/credentials/{CREDENTIAL}")
        self.assertEqual(status, 200)
        self.assertNotIn("key_reference", result)
        self.assertNotIn("lease", result)
        status, result, _ = call(self.app, "POST", f"/v1/credentials/{CREDENTIAL}/prepare",
            {"rpId": "example.test", "clientDataHash": "a" * 64}, request_key="2" * 32)
        self.assertEqual(status, 200)
        self.assertEqual(result["counter"], 1)
        self.assertNotIn("signature", result)
        self.assertNotIn("userVerified", result)

    def test_invalid_duplicate_oversized_and_non_utf8_json_is_rejected(self):
        for data in [b'[{"rpId":"example.test"}]', b'{"rpId":"example.test","rpId":"other.test"}', b'{"rpId":NaN}', b'\xff']:
            status, _, _ = call(self.app, "POST", "/v1/reservations", overrides={"wsgi.input": BytesIO(data), "CONTENT_LENGTH": str(len(data))})
            self.assertEqual(status, 400)
        for overrides in [{"CONTENT_LENGTH": "8193"}, {"CONTENT_LENGTH": "-1"}, {"CONTENT_TYPE": "text/plain"}]:
            self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"}, overrides=overrides)[0], 400)
        self.assertIsNone(self.store.read(caller().partition, "owner"))

    def test_errors_are_no_store_and_do_not_expose_exception_details(self):
        class Broken(MemoryStore):
            def read(self, *args):
                raise StorageUnavailable("SYNTHETIC-PRIVATE-DETAIL")
        app = BrokerApplication(Coordinator(Broken(), frozenset([APP])), verifier())
        for status, result, headers in [call(app, "POST", "/v1/reservations", {"rpId": "example.test"}),
                call(self.app, "GET", "/unknown"), call(self.app, "GET", "/unknown", overrides={"HTTP_AUTHORIZATION": ""})]:
            self.assertIn(status, [401, 404, 503])
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["Pragma"], "no-cache")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertNotIn("SYNTHETIC-PRIVATE-DETAIL", json.dumps(result))

    def corrupt_cached_result(self, overrides):
        tx = Transaction(self.store, caller().partition)
        row = "request-" + "1" * 32
        prior = tx.get(row)
        tx.put(row, {**prior, "result": {**prior["result"], **overrides}})
        tx.commit()

    def test_corrupt_cached_reservation_cannot_expose_an_internal_structure(self):
        self.assertEqual(call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})[0], 201)
        original = self.store.read(caller().partition, "request-" + "1" * 32).value["result"]
        for overrides in [{"credential_id": {"private": "SYNTHETIC-PRIVATE-DETAIL"}}, {"expires_at": True}, {"state": "active"}]:
            self.corrupt_cached_result({**original, **overrides})
            status, result, headers = call(self.app, "POST", "/v1/reservations", {"rpId": "example.test"})
            self.assertEqual(status, 503)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertNotIn("SYNTHETIC-PRIVATE-DETAIL", json.dumps(result))

    def test_corrupt_cached_preparation_cannot_expose_internal_values(self):
        seed_active(self.store, caller())
        path = f"/v1/credentials/{CREDENTIAL}/prepare"
        body = {"rpId": "example.test", "clientDataHash": "a" * 64}
        self.assertEqual(call(self.app, "POST", path, body)[0], 200)
        self.corrupt_cached_result({"nonce": {"private": "SYNTHETIC-PRIVATE-DETAIL"}})
        status, result, _ = call(self.app, "POST", path, body)
        self.assertEqual(status, 503)
        self.assertNotIn("SYNTHETIC-PRIVATE-DETAIL", json.dumps(result))
        self.assertEqual(call(self.app, "GET", f"/v1/credentials/{CREDENTIAL}")[1]["counter"], 1)


if __name__ == "__main__":
    unittest.main()
