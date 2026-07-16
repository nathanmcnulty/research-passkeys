import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FUNCTION_ROOT = ROOT / "function-app"
PYTHON_ROOT = FUNCTION_ROOT / "python/keyvault-passkey-http"
POWERSHELL_ROOT = FUNCTION_ROOT / "powershell/keyvault-passkey-http"


class CaptureContractTests(unittest.TestCase):
    def test_contract_schemas_are_valid_json(self):
        for name in ("passkey-catalog-record.schema.json", "passkey-capture-context.schema.json"):
            with (ROOT / "contracts" / name).open(encoding="utf-8") as stream:
                json.load(stream)

    def test_both_templates_define_capture_resources_and_guards(self):
        required = {
            "PASSKEY_CAPTURE_TABLE_NAME",
            "PASSKEY_CAPTURE_CONTAINER_NAME",
            "PASSKEY_CAPTURE_MAX_BYTES",
            "PASSKEY_CAPTURE_PROVENANCE_DAYS",
            "PASSKEY_ENABLE_DEV_SECRET_EXPORT",
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            "Microsoft.KeyVault/vaults/secrets/setSecret/action",
            "Microsoft.KeyVault/vaults/secrets/delete",
            "enableVirtualNetworkIntegration",
            "existingVirtualNetworkName",
            "existingVirtualNetworkResourceGroupName",
            "existingFunctionSubnetName",
            "networkIntegrationEnabled",
        }
        for template in (
            PYTHON_ROOT / "infra/main.bicep",
            POWERSHELL_ROOT / "infra/main.bicep",
        ):
            content = template.read_text(encoding="utf-8")
            self.assertTrue(required.issubset(set(item for item in required if item in content)), template)
            self.assertIn("!productionProfile && enableDevelopmentSecretExport", content)

    def test_python_and_powershell_expose_capture_routes(self):
        expected = {
            "passkeys/{recordId}/contexts",
            "passkeys/{recordId}/contexts/{captureId}",
            "passkeys/{recordId}/contexts/{captureId}/export",
            "passkeys/{recordId}/login-context/export",
            "passkeys/{recordId}/login-context",
            "entra/passkeys/{recordId}/login",
            "okta/passkeys/{recordId}/login",
        }
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")
        python_routes = set(re.findall(r'route="([^"]+)"', python_source))
        powershell_routes = set()
        for function_json in (POWERSHELL_ROOT / "src").glob("*/function.json"):
            payload = json.loads(function_json.read_text(encoding="utf-8"))
            powershell_routes.update(binding["route"] for binding in payload["bindings"] if "route" in binding)
        self.assertTrue(expected.issubset(python_routes))
        self.assertTrue(expected.issubset(powershell_routes))

    def test_queue_messages_do_not_embed_plaintext_session_fields(self):
        entra_queue = (POWERSHELL_ROOT / "src/QueueEntraPasskeyRegistrationViaEstsAuth/run.ps1").read_text(encoding="utf-8")
        okta_queue = (POWERSHELL_ROOT / "src/QueueOktaPasskeyRegistrationViaIdxSession/run.ps1").read_text(encoding="utf-8")
        self.assertNotIn("estsAuth = $estsAuthCookie", entra_queue)
        self.assertNotIn("cookieHeader = $cookieHeader", okta_queue)
        self.assertNotIn("stateHandle = $stateHandle", okta_queue)
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")
        self.assertIn('queue_message.pop("estsAuth", None)', python_source)
        self.assertIn('queue_message.pop("cookieHeader", None)', python_source)
        self.assertIn('queue_message.pop("stateHandle", None)', python_source)

    def test_entra_queue_worker_replays_normalized_capture_context(self):
        powershell_worker = (
            POWERSHELL_ROOT / "src/ProcessEntraPasskeyRegistrationViaEstsAuth/run.ps1"
        ).read_text(encoding="utf-8")
        powershell_helper = (
            POWERSHELL_ROOT / "src/shared/PasskeyFunctionHelpers.ps1"
        ).read_text(encoding="utf-8")
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")

        self.assertIn("Get-EstsAuthCookieFromSource -CookieSource $capturedBody", powershell_worker)
        self.assertIn("$message.redirectUri ?? $message.redirecturi", powershell_worker)
        self.assertIn("Get-RequestValue -Body $Body -Request $Request -Names @('redirectUri', 'redirecturi')", powershell_helper)
        self.assertIn("extract_ests_auth_cookie_value(captured_payload)", python_source)
        self.assertIn('message_payload.get("redirectUri")', python_source)

    def test_capture_user_agent_does_not_override_ests_replay_profile(self):
        powershell_helper = (
            POWERSHELL_ROOT / "src/shared/PasskeyFunctionHelpers.ps1"
        ).read_text(encoding="utf-8")
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")

        self.assertIn("-Names @('userAgent', 'useragent')", powershell_helper)
        self.assertNotIn("-Names @('userAgent', 'useragent', 'user_agent')", powershell_helper)
        self.assertIn('_get_request_value(body, req, "userAgent", "useragent")', python_source)
        self.assertNotIn('_get_request_value(body, req, "userAgent", "useragent", "user_agent")', python_source)

    def test_ests_auth_registration_keeps_sync_and_queue_routes_distinct(self):
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")
        powershell_direct = json.loads(
            (POWERSHELL_ROOT / "src/RegisterEntraPasskeyViaEstsAuth/function.json").read_text(encoding="utf-8")
        )
        powershell_queue = json.loads(
            (POWERSHELL_ROOT / "src/QueueEntraPasskeyRegistrationViaEstsAuth/function.json").read_text(encoding="utf-8")
        )
        self.assertIn('route="entra/passkeys/register/estsauth"', python_source)
        self.assertIn('route="entra/passkeys/register/estsauth/queue"', python_source)
        self.assertEqual(powershell_direct["bindings"][0]["route"], "entra/passkeys/register/estsauth")
        self.assertEqual(powershell_queue["bindings"][0]["route"], "entra/passkeys/register/estsauth/queue")
        self.assertTrue(any(binding.get("type") == "queue" for binding in powershell_queue["bindings"]))

    def test_powershell_catalog_defaults_optional_sign_count(self):
        helper = (POWERSHELL_ROOT / "src/shared/PasskeyFunctionHelpers.ps1").read_text(encoding="utf-8")
        self.assertIn("function Get-PasskeyObjectValue", helper)
        self.assertIn("Get-PasskeyObjectValue -Object $Credential -Names @('signCount')", helper)
        self.assertIn("$signCount = if ($null -eq $signCountValue", helper)

    def test_powershell_secret_expiry_handles_unwrapped_datetime(self):
        helper = (POWERSHELL_ROOT / "src/shared/PasskeyFunctionHelpers.ps1").read_text(encoding="utf-8")
        self.assertIn("if ($null -ne $ExpiresAt)", helper)
        self.assertNotIn("$ExpiresAt.HasValue", helper)

    def test_registration_http_errors_are_logged_without_write_error(self):
        powershell_direct = (POWERSHELL_ROOT / "src/RegisterEntraPasskeyViaEstsAuth/run.ps1").read_text(encoding="utf-8")
        powershell_queue = (POWERSHELL_ROOT / "src/QueueEntraPasskeyRegistrationViaEstsAuth/run.ps1").read_text(encoding="utf-8")
        self.assertIn("Write-Warning -Message", powershell_direct)
        self.assertIn("Write-Warning -Message", powershell_queue)
        self.assertNotIn("Write-Error -Message", powershell_direct)
        self.assertNotIn("Write-Error -Message", powershell_queue)
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")
        self.assertIn('logger.exception("RegisterEntraPasskeyViaEstsAuth failed")', python_source)
        self.assertIn('logger.exception("QueueEntraPasskeyRegistrationViaEstsAuth failed")', python_source)

    def test_export_responses_are_no_store(self):
        python_source = (PYTHON_ROOT / "src/function_app.py").read_text(encoding="utf-8")
        helper = (POWERSHELL_ROOT / "src/shared/PasskeyFunctionHelpers.ps1").read_text(encoding="utf-8")
        self.assertIn('"Cache-Control": "no-store"', python_source)
        self.assertIn("$response.Headers['Cache-Control'] = 'no-store'", helper)

    def test_development_nat_validation_is_opt_in(self):
        deploy_script = (ROOT / "scripts/deployment/Deploy-FunctionSample.ps1").read_text(encoding="utf-8")
        self.assertIn("ExistingNatGatewayName", deploy_script)
        self.assertIn("enableVirtualNetworkIntegration=true", deploy_script)
        self.assertIn("cannot be shared with a newly-created VNet", deploy_script)


if __name__ == "__main__":
    unittest.main()
