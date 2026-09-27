import ast
import base64
import binascii
import json
import os
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "function-app/python/keyvault-passkey-http/src/function_app.py"
TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "33333333-3333-3333-3333-333333333333"
OBJECT = "22222222-2222-2222-2222-222222222222"


class PasskeySecurityError(Exception):
    pass


def load_identity_parser():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_get_caller_identity")
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), function],
        type_ignores=[],
    )
    namespace = {"base64": base64, "binascii": binascii, "json": json, "os": os, "uuid": uuid,
                 "PasskeySecurityError": PasskeySecurityError}
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
    return namespace["_get_caller_identity"]


def request(*, provider="aad", tenant=TENANT, object_id=OBJECT, extra_claims=(), header_provider="aad"):
    claims = [{"typ": "tid", "val": tenant}, {"typ": "oid", "val": object_id}, *extra_claims]
    principal = {"auth_typ": provider, "claims": claims}
    encoded = base64.b64encode(json.dumps(principal).encode()).decode()
    return SimpleNamespace(headers={"X-MS-CLIENT-PRINCIPAL": encoded,
                                    "X-MS-CLIENT-PRINCIPAL-IDP": header_provider})


class CallerIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parse = staticmethod(load_identity_parser())

    def test_accepts_matching_entra_identity(self):
        with patch.dict(os.environ, {"PASSKEY_TENANT_ID": TENANT}):
            self.assertEqual(self.parse(request()), {"tenantId": TENANT, "objectId": OBJECT})

    def test_rejects_wrong_provider_or_tenant(self):
        with patch.dict(os.environ, {"PASSKEY_TENANT_ID": TENANT}):
            for candidate in (request(provider="google"), request(header_provider="google"),
                              request(tenant=OTHER_TENANT)):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(PasskeySecurityError):
                        self.parse(candidate)

    def test_rejects_missing_or_conflicting_immutable_claims(self):
        with patch.dict(os.environ, {"PASSKEY_TENANT_ID": TENANT}):
            for candidate in (request(object_id=""),
                              request(extra_claims=({"typ": "oid", "val": str(uuid.uuid4())},)),
                              request(extra_claims=({"typ": "http://schemas.microsoft.com/identity/claims/tenantid", "val": OTHER_TENANT},))):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(PasskeySecurityError):
                        self.parse(candidate)


if __name__ == "__main__":
    unittest.main()
