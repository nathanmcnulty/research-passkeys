import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "function-app/powershell/keyvault-passkey-http"
SOURCE = SAMPLE / "src"
PYTHON_SAMPLE = ROOT / "function-app/python/keyvault-passkey-http"
PYTHON_SOURCE = PYTHON_SAMPLE / "src/function_app.py"


class BrokerContractTests(unittest.TestCase):
    def test_broker_routes_require_function_keys(self):
        expected = {
            "GetPasskeyBrokerConfiguration": ("broker/config", "get"),
            "GetEntraPasskeyAccessToken": ("entra/passkeys/{recordId}/token", "post"),
        }
        for function_name, (route, method) in expected.items():
            payload = json.loads((SOURCE / function_name / "function.json").read_text(encoding="utf-8"))
            trigger = next(binding for binding in payload["bindings"] if binding["type"] == "httpTrigger")
            self.assertEqual(trigger["authLevel"], "function")
            self.assertEqual(trigger["route"], route)
            self.assertIn(method, trigger["methods"])

        python_source = PYTHON_SOURCE.read_text(encoding="utf-8")
        self.assertIn('route="broker/config", methods=["GET"], auth_level=func.AuthLevel.FUNCTION', python_source)
        self.assertIn(
            'route="entra/passkeys/{recordId}/token", methods=["POST"], auth_level=func.AuthLevel.FUNCTION',
            python_source,
        )

    def test_token_endpoint_is_profile_limited_and_no_store(self):
        helper = (SOURCE / "shared/PasskeyFunctionHelpers.ps1").read_text(encoding="utf-8")
        endpoint = (SOURCE / "GetEntraPasskeyAccessToken/run.ps1").read_text(encoding="utf-8")
        self.assertIn("'microsoftgraph'", helper)
        self.assertIn("'azureresourcemanager'", helper)
        self.assertIn("GraphAllowedScopes", helper)
        self.assertIn("code_challenge_method = 'S256'", helper)
        self.assertIn("Authorization response state validation failed", helper)
        self.assertIn("code_verifier = $pkce.Verifier", helper)
        self.assertNotIn("refresh_token", helper)
        self.assertIn("-NoStore", endpoint)
        self.assertIn("Write-Warning 'Passkey token acquisition failed during the upstream authentication exchange.'", endpoint)

        python_source = PYTHON_SOURCE.read_text(encoding="utf-8")
        self.assertIn('profile.lower() == "microsoftgraph"', python_source)
        self.assertIn('profile.lower() == "azureresourcemanager"', python_source)
        self.assertIn('"code_challenge_method": "S256"', python_source)
        self.assertIn('"code_verifier": verifier', python_source)
        self.assertIn('raise RuntimeError("Authorization response state validation failed.")', python_source)
        self.assertNotIn('"refresh_token"', python_source)
        self.assertIn('return _no_store_response(200, {"success": True, **token})', python_source)

    def test_broker_settings_are_deployed(self):
        template = (SAMPLE / "infra/main.bicep").read_text(encoding="utf-8")
        deploy = (ROOT / "scripts/deployment/Deploy-FunctionSample.ps1").read_text(encoding="utf-8")
        for setting in ("PASSKEY_TOKEN_CLIENT_ID", "PASSKEY_TOKEN_REDIRECT_URI", "PASSKEY_GRAPH_ALLOWED_SCOPES"):
            self.assertIn(setting, template)
            self.assertIn(setting, deploy)
        self.assertIn("param tokenClientId string", template)
        self.assertIn("TokenClientId was not supplied", deploy)
        self.assertIn("if (-not [string]::IsNullOrWhiteSpace($TokenClientId))", deploy)
        self.assertIn("'python-keyvault-passkey-http'", deploy)
        self.assertNotIn("if ($TemplateId -eq 'powershell-keyvault-passkey-http')", deploy)
        python_template = (PYTHON_SAMPLE / "infra/main.bicep").read_text(encoding="utf-8")
        for setting in ("PASSKEY_TOKEN_CLIENT_ID", "PASSKEY_TOKEN_REDIRECT_URI", "PASSKEY_GRAPH_ALLOWED_SCOPES"):
            self.assertIn(setting, python_template)
        self.assertIn("param tokenClientId string", python_template)

    def test_ests_auth_responses_are_no_store(self):
        for function_name in ("LoginWithEntraPasskey", "LoginWithStoredEntraPasskey"):
            content = (SOURCE / function_name / "run.ps1").read_text(encoding="utf-8")
            self.assertIn("-NoStore", content)

        python_source = PYTHON_SOURCE.read_text(encoding="utf-8")
        for function_name in ("login_with_entra_passkey_http", "login_with_stored_entra_passkey_http"):
            function_body = python_source.split(f"def {function_name}", 1)[1].split("\n@app.function_name", 1)[0]
            self.assertIn("_no_store_response", function_body)


if __name__ == "__main__":
    unittest.main()
