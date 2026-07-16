import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = ROOT / "function-app/powershell/keyvault-passkey-http"
PYTHON = ROOT / "function-app/python/keyvault-passkey-http"


class BrowserExtensionAdapterContractTests(unittest.TestCase):
    def test_python_and_powershell_expose_the_same_function_names(self):
        powershell_names = {
            path.parent.name
            for path in (POWERSHELL / "src").glob("*/function.json")
        }
        python_source = (PYTHON / "src/function_app.py").read_text(encoding="utf-8")
        python_names = set(re.findall(r'@app\.function_name\(name="([^"]+)"\)', python_source))
        self.assertEqual(powershell_names, python_names)

    def test_powershell_browser_routes_are_easy_auth_only(self):
        expected = {
            "ListPasskeyCatalogRecords": ("passkeys", "get"),
            "GetPasskeyCatalogRecord": ("passkeys/{recordId}", "get"),
            "GetPasskeyBrowserContext": ("passkeys/{recordId}/browser-context", "get"),
            "DeletePasskeyCatalogRecord": ("passkeys/{recordId}", "delete"),
            "AssertWithStoredPasskey": ("passkeys/{recordId}/assert", "post"),
        }
        for name, (route, method) in expected.items():
            payload = json.loads((POWERSHELL / "src" / name / "function.json").read_text(encoding="utf-8"))
            trigger = next(binding for binding in payload["bindings"] if binding["type"] == "httpTrigger")
            self.assertEqual(trigger["authLevel"], "anonymous")
            self.assertEqual(trigger["route"], route)
            self.assertIn(method, trigger["methods"])

    def test_queue_ingress_keeps_function_keys(self):
        for name in ("QueueEntraPasskeyRegistrationViaEstsAuth", "QueueOktaPasskeyRegistrationViaIdxSession"):
            payload = json.loads((POWERSHELL / "src" / name / "function.json").read_text(encoding="utf-8"))
            trigger = next(binding for binding in payload["bindings"] if binding["type"] == "httpTrigger")
            self.assertEqual(trigger["authLevel"], "function")

    def test_both_templates_enable_easy_auth_with_exact_queue_exclusions(self):
        expected_paths = (
            "/api/entra/passkeys/register/estsauth/queue",
            "/api/okta/passkeys/register/idx/queue",
        )
        for sample in (POWERSHELL, PYTHON):
            template = (sample / "infra/main.bicep").read_text(encoding="utf-8")
            self.assertIn("name: 'authsettingsV2'", template)
            self.assertIn("requireAuthentication: true", template)
            self.assertIn("unauthenticatedClientAction: 'Return401'", template)
            self.assertIn("param browserExtensionClientId string", template)
            for path in expected_paths:
                self.assertIn(path, template)

    def test_python_exposes_constrained_assertion_route(self):
        source = (PYTHON / "src/function_app.py").read_text(encoding="utf-8")
        self.assertIn('route="passkeys/{recordId}/assert"', source)
        self.assertIn('"signatureFormat": "ieee-p1363"', source)
        self.assertNotIn('route="signDigest"', source)

    def test_python_exposes_browser_context_and_delete_routes(self):
        source = (PYTHON / "src" / "function_app.py").read_text(encoding="utf-8")
        self.assertIn('route="passkeys/{recordId}/browser-context"', source)
        self.assertIn('route="passkeys/{recordId}", methods=["DELETE"]', source)
        self.assertIn('"userAgent": user_agent', source)

    def test_delete_routes_remove_catalog_context_and_signing_key(self):
        powershell_source = (POWERSHELL / "src/shared/PasskeyFunctionHelpers.ps1").read_text(encoding="utf-8")
        powershell_route = (POWERSHELL / "src/DeletePasskeyCatalogRecord/run.ps1").read_text(encoding="utf-8")
        python_source = (PYTHON / "src/function_app.py").read_text(encoding="utf-8")
        self.assertIn("function Remove-PasskeyKeyVaultKey", powershell_source)
        self.assertIn("function Remove-PasskeyCatalogRecord", powershell_source)
        self.assertIn("Remove-PasskeyKeyVaultSecret", powershell_route)
        self.assertIn("Remove-PasskeyKeyVaultKey", powershell_route)
        self.assertIn("_delete_key_vault_secret", python_source)
        self.assertIn("_delete_key_vault_key", python_source)
        self.assertIn("_delete_catalog_record", python_source)

    def test_deployment_preserves_single_graph_permission_as_an_array(self):
        deploy = (ROOT / "scripts/deployment/Deploy-FunctionSample.ps1").read_text(encoding="utf-8")
        self.assertIn("ConvertTo-Json -InputObject $GraphDelegatedPermissions", deploy)
        self.assertNotIn("$GraphDelegatedPermissions | ConvertTo-Json", deploy)


if __name__ == "__main__":
    unittest.main()
