import ast
import json
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "function-app/python/keyvault-passkey-http/src/function_app.py"
FUNCTIONS = {
    "_get_body_value",
    "_get_secret_body_value",
    "_resolve_okta_access_token",
    "_json_response",
    "_no_store_response",
    "start_okta_myaccount_webauthn_registration_http",
}


class PasskeyValidationError(Exception):
    pass


class FakeHttpResponse:
    def __init__(self, body, *, status_code, mimetype, headers=None):
        self.body = json.loads(body)
        self.status_code = status_code
        self.mimetype = mimetype
        self.headers = headers or {}


def load_route():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert len(selected) == len(FUNCTIONS)
    for node in selected:
        node.decorator_list = []
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
        type_ignores=[],
    )
    outbound_tokens = []
    namespace = {
        "json": json,
        "func": SimpleNamespace(HttpResponse=FakeHttpResponse),
        "PasskeyValidationError": PasskeyValidationError,
        "_get_request_body": lambda req: req.body,
        "_resolve_okta_domain": lambda body, req: "example.okta.com",
        "start_myaccount_registration": lambda *, okta_domain, access_token: outbound_tokens.append(access_token) or {"ok": True},
    }
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
    return namespace["start_okta_myaccount_webauthn_registration_http"], outbound_tokens


class OktaTokenBoundaryTests(unittest.TestCase):
    def test_entra_authorization_header_is_not_forwarded_to_okta(self):
        route, outbound_tokens = load_route()
        request = SimpleNamespace(body={}, headers={"Authorization": "Bearer entra-api-token"})
        response = route(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(outbound_tokens, [])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_explicit_okta_body_token_is_the_only_outbound_token(self):
        route, outbound_tokens = load_route()
        request = SimpleNamespace(
            body={"oktaAccessToken": "okta-user-token"},
            headers={"Authorization": "Bearer entra-api-token"},
        )
        response = route(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(outbound_tokens, ["okta-user-token"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_nonstring_or_empty_body_token_fails_closed(self):
        route, outbound_tokens = load_route()
        for value in ({"token": "wrong-type"}, "  ", None):
            with self.subTest(value=value):
                response = route(SimpleNamespace(body={"accessToken": value}, headers={}))
                self.assertEqual(response.status_code, 400)
        self.assertEqual(outbound_tokens, [])


if __name__ == "__main__":
    unittest.main()
