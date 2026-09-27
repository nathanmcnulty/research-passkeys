import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "function-app/python/keyvault-passkey-http/src/function_app.py"
HTTP_FUNCTIONS = (
    "delete_passkey_catalog_record_http",
    "register_entra_passkey_via_tap_http",
    "register_entra_passkey_via_ests_auth_http",
    "queue_entra_passkey_registration_via_ests_auth_http",
    "register_okta_passkey_via_idx_session_http",
    "queue_okta_passkey_registration_via_idx_session_http",
)
WORKERS = (
    "process_entra_passkey_registration_via_ests_auth_queue",
    "process_okta_passkey_registration_via_idx_session_queue",
)


class LegacyMutationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in (*HTTP_FUNCTIONS, *WORKERS)]
        for node in selected:
            node.decorator_list = []
        module = ast.Module(
            body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
            type_ignores=[],
        )
        cls.namespace = {"_legacy_key_mutation_disabled": lambda: (501, "no-store")}
        exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), cls.namespace)

    def test_http_mutations_return_before_touching_request_or_queue(self):
        self.assertEqual(len(HTTP_FUNCTIONS), 6)
        for name in HTTP_FUNCTIONS:
            with self.subTest(name=name):
                arguments = (None, None) if name.startswith("queue_") else (None,)
                self.assertEqual(self.namespace[name](*arguments), (501, "no-store"))

    def test_queue_workers_reject_before_touching_message(self):
        for name in WORKERS:
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, "disabled"):
                    self.namespace[name](None)

    def test_both_templates_disable_mutation_functions(self):
        function_names = (
            "DeletePasskeyCatalogRecord", "RegisterEntraPasskeyViaTap", "RegisterEntraPasskeyViaEstsAuth",
            "QueueEntraPasskeyRegistrationViaEstsAuth", "ProcessEntraPasskeyRegistrationViaEstsAuth",
            "RegisterOktaPasskeyViaIdxSession", "QueueOktaPasskeyRegistrationViaIdxSession",
            "ProcessOktaPasskeyRegistrationViaIdxSession",
        )
        for language in ("python", "powershell"):
            template = (ROOT / f"function-app/{language}/keyvault-passkey-http/infra/main.bicep").read_text(encoding="utf-8")
            self.assertIn("publicNetworkAccess: 'Disabled'", template)
            for name in function_names:
                with self.subTest(language=language, name=name):
                    self.assertIn(f"'AzureWebJobs.{name}.Disabled': 'true'", template)


if __name__ == "__main__":
    unittest.main()
