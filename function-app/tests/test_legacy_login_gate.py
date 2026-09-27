import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "function-app/python/keyvault-passkey-http/src/function_app.py"
FUNCTIONS = (
    "get_entra_passkey_access_token_http",
    "login_with_stored_entra_passkey_http",
    "login_with_stored_okta_passkey_http",
    "login_with_entra_passkey_http",
    "login_with_okta_passkey_http",
    "test_okta_passkey_login_via_idx_session_http",
)
FUNCTION_NAMES = (
    "GetEntraPasskeyAccessToken",
    "LoginWithStoredEntraPasskey",
    "LoginWithStoredOktaPasskey",
    "LoginWithEntraPasskey",
    "LoginWithOktaPasskey",
    "TestOktaPasskeyLoginViaIdxSession",
)


class LegacyLoginGateTests(unittest.TestCase):
    def test_python_routes_return_before_request_or_token_access(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
        self.assertEqual(len(selected), len(FUNCTIONS))
        for node in selected:
            node.decorator_list = []
        module = ast.Module(
            body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
            type_ignores=[],
        )
        namespace = {"_legacy_login_disabled": lambda: (501, "no-store")}
        exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
        for name in FUNCTIONS:
            with self.subTest(name=name):
                self.assertEqual(namespace[name](None), (501, "no-store"))

    def test_both_templates_disable_login_and_token_routes(self):
        for language in ("python", "powershell"):
            template = (ROOT / f"function-app/{language}/keyvault-passkey-http/infra/main.bicep").read_text(encoding="utf-8")
            for name in FUNCTION_NAMES:
                with self.subTest(language=language, name=name):
                    self.assertIn(f"'AzureWebJobs.{name}.Disabled': 'true'", template)


if __name__ == "__main__":
    unittest.main()
