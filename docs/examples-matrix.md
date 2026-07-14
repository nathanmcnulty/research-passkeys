# Example parity and naming map

This document tracks the example surfaces by language and identity provider. It is the
source of truth for local example names and parity; it deliberately does not change
hosted API routes by itself.

## Naming convention

Use the provider immediately after the PowerShell verb or Python action:

| Surface | Shape | Example |
| --- | --- | --- |
| PowerShell | `<Verb>-<Provider><Capability>[Via<Mechanism>].ps1` | `Register-EntraPasskeyViaTap.ps1` |
| Python | `<verb>_<provider>_<capability>[_via_<mechanism>].py` | `register_entra_passkey_via_tap.py` |

Use these verbs consistently:

- `Register` / `register`: enroll a credential.
- `Invoke` / `invoke`: perform a complete login or operational action.
- `Test` / `test`: diagnostic, smoke-test, or browser-session handoff harness.
- `Initialize` / `initialize`: provision prerequisites rather than enroll a credential.

Keep `KeyVault` in the name when the script's primary purpose is Key Vault setup or
Key Vault-specific plumbing. Keep the identity provider in the name even when the
implementation uses shared WebAuthn or Key Vault helpers.

## Parity matrix

Legend: ✅ implemented, ◐ combined surface or partial parity, — missing, N/A not a
meaningful combination for that flow.

| Example type | PowerShell / Entra | Python / Entra | PowerShell / Okta | Python / Okta | Next parity action |
| --- | --- | --- | --- | --- | --- |
| Local passkey registration via TAP | ✅ `scripts/entra/Register-EntraKeyVaultPasskey.ps1`; reference TAP script | ✅ `samples/entra/register_entra_keyvault_passkey.py tap` | N/A | N/A | TAP is Entra-only. |
| Local passkey registration via ESTSAUTH | ✅ `scripts/entra/reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1` | ✅ `samples/entra/register_entra_keyvault_passkey.py estsauth` | N/A | N/A | ESTSAUTH is Entra-only. |
| Local login with a stored Key Vault credential | ✅ `scripts/entra/reference/Invoke-EntraPasskeyLogin.ps1` | ✅ `samples/entra/invoke_entra_passkey_login.py` | ✅ `scripts/okta/Invoke-OktaPasskeyLogin.ps1` | ✅ `samples/okta/passkey-login/invoke_okta_passkey_login.py` | Direct Okta IDX login is a development harness. |
| Okta MyAccount registration-start smoke test | N/A | N/A | ✅ `scripts/okta/Test-OktaMyAccountWebAuthn.ps1` | ✅ `samples/okta/test_okta_myaccount_webauthn.py` | Both support a supplied user token; PKCE requires a public client. |
| Okta IDX browser-session registration | N/A | N/A | ✅ `scripts/okta/Register-OktaKeyVaultPasskeyViaIdxSession.ps1` | ✅ `samples/okta/passkey-register/register_okta_passkey_via_idx_session.py` | Browser-session handoff is development-only. |
| Okta IDX browser-session login | N/A | N/A | ✅ `scripts/okta/Test-OktaPasskeyLoginViaIdxSession.ps1` | ✅ `samples/okta/passkey-login/test_okta_passkey_login_via_idx_session.py` | Browser-session handoff is development-only. |
| Device-code delegated bootstrap | ✅ `samples/entra/device-code-bootstrap/Invoke-EntraDeviceCodeBootstrap.ps1` | ✅ `samples/entra/invoke_entra_device_code_bootstrap.py` | N/A | N/A | Entra delegated bootstrap. |
| Hosted Entra direct registration via TAP | ✅ PowerShell Function `RegisterEntraPasskeyViaTap` | ✅ Python Function `RegisterEntraPasskeyViaTap` | N/A | N/A | Route: `/api/entra/passkeys/register/tap`. |
| Hosted Entra direct registration via ESTSAUTH | ✅ PowerShell Function `RegisterEntraPasskeyViaEstsAuth` | ✅ Python Function `RegisterEntraPasskeyViaEstsAuth` | N/A | N/A | Route: `/api/entra/passkeys/register/estsauth`. |
| Hosted Entra login with a stored credential | ✅ PowerShell Function `LoginWithEntraPasskey` | ✅ Python Function `LoginWithEntraPasskey` | N/A | N/A | Route: `/api/entra/passkeys/login`. |
| Hosted Okta MyAccount registration-start | N/A | N/A | ✅ `StartOktaMyAccountWebAuthnRegistration` | ✅ `StartOktaMyAccountWebAuthnRegistration` | Requires a user-scoped Okta access token. Route: `/api/okta/passkeys/register/myaccount`. |
| Hosted Okta IDX registration | N/A | N/A | ✅ `RegisterOktaPasskeyViaIdxSession` / `QueueOktaPasskeyRegistrationViaIdxSession` | ✅ `RegisterOktaPasskeyViaIdxSession` / `QueueOktaPasskeyRegistrationViaIdxSession` | Direct and queued browser-session routes; development-only. Queue: `PASSKEY_OKTA_REGISTRATION_QUEUE_NAME`. |
| Hosted Okta IDX login | N/A | N/A | ✅ `LoginWithOktaPasskey` / `TestOktaPasskeyLoginViaIdxSession` | ✅ `LoginWithOktaPasskey` / `TestOktaPasskeyLoginViaIdxSession` | Direct route `/api/okta/passkeys/login` and active-session route `/api/okta/passkeys/login/idx`. |
| Hosted Entra ESTSAUTH queue registration | ✅ `Invoke-EntraQueuePasskeyRegistration.ps1` and PowerShell Function | ✅ `submit_entra_queue_passkey_registration.py` and Python Function | N/A | N/A | Route: `/api/entra/passkeys/register/estsauth/queue`; status: `/api/entra/passkeys/register/status/{requestId}`. |
| Hosted Okta IDX queue registration | N/A | N/A | ✅ `QueueOktaPasskeyRegistrationViaIdxSession` + `ProcessOktaPasskeyRegistrationViaIdxSession` | ✅ `QueueOktaPasskeyRegistrationViaIdxSession` + `ProcessOktaPasskeyRegistrationViaIdxSession` | Route: `/api/okta/passkeys/register/idx/queue`; status: `/api/okta/passkeys/register/status/{requestId}`; use the separate `PASSKEY_OKTA_REGISTRATION_QUEUE_NAME`. |
| Azure Automation runbook registration/login | ✅ TAP, ESTSAUTH, and login runbooks | N/A (PowerShell host) | N/A | N/A | Rename runbooks to Entra; do not create Python runbooks solely for parity. |

The four local language/provider combinations are now represented. Hosted and
TAP/ESTSAUTH rows remain Entra-specific rather than incomplete Okta implementations;
the browser-session Okta scripts are intentionally development-only.

## Primary script rename map

These are the proposed physical renames for the local example scripts. References in
README files, tests, packaging scripts, and copied Function assets must be updated in
the same change.

### PowerShell

| Former path | Current path | Reason |
| --- | --- | --- |
| `powershell/scripts/Register-KeyVaultPasskey.ps1` | `powershell/scripts/entra/Register-EntraKeyVaultPasskey.ps1` | Curated Entra registration wrapper whose primary output is a Key Vault-backed credential. |
| `powershell/scripts/reference/Initialize-PasskeyKeyVault.ps1` | `powershell/scripts/entra/reference/Initialize-EntraPasskeyKeyVault.ps1` | Provisions Entra/Graph prerequisites. |
| `powershell/scripts/reference/New-KeyVaultPasskey.ps1` | `powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1` | Registers a locally generated software credential in Entra. |
| `powershell/scripts/reference/PasskeyLogin.ps1` | `powershell/scripts/entra/reference/Invoke-EntraPasskeyLogin.ps1` | Full Entra login action; matches the requested `Invoke` convention. |
| `powershell/scripts/reference/Register-KeyVaultPasskeyViaESTSAuth.ps1` | `powershell/scripts/entra/reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1` | Explicit Entra provider, Key Vault output, and mechanism. |
| `powershell/scripts/reference/Register-KeyVaultPasskeyViaTAP.ps1` | `powershell/scripts/entra/reference/Register-EntraKeyVaultPasskeyViaTap.ps1` | Explicit Entra provider, Key Vault output, and mechanism. |
| `powershell/samples/device-code-bootstrap/Invoke-DeviceCodeBootstrap.ps1` | `powershell/samples/entra/device-code-bootstrap/Invoke-EntraDeviceCodeBootstrap.ps1` | Device-code flow targets Entra delegated auth. |
| `powershell/scripts/Register-KeyVaultOktaPasskeyViaIdxSession.ps1` | `powershell/scripts/okta/Register-OktaKeyVaultPasskeyViaIdxSession.ps1` | Provider immediately follows the verb while preserving the Key Vault-backed implementation. |
| `powershell/scripts/Test-KeyVaultOktaPasskeyLogin.ps1` | `powershell/scripts/okta/Invoke-OktaPasskeyLogin.ps1` | Complete login action rather than a generic test name. |
| `powershell/scripts/Test-KeyVaultOktaPasskeyViaIdxSession.ps1` | `powershell/scripts/okta/Test-OktaPasskeyLoginViaIdxSession.ps1` | Retains `Test` because it is a manual browser-session harness. |
| `powershell/scripts/Test-OktaMyAccountWebAuthn.ps1` | *(no change)* | Already follows the provider-first naming rule. |

### Python

| Former path | Current path | Reason |
| --- | --- | --- |
| `python/samples/passkey-register/register_keyvault_passkey.py` | `python/samples/entra/register_entra_keyvault_passkey.py` | The TAP and ESTSAUTH subcommands are Entra-specific and create Key Vault-backed credentials. |
| `python/samples/passkey-login/login_keyvault_passkey.py` | `python/samples/entra/invoke_entra_passkey_login.py` | Matches `Invoke-EntraPasskeyLogin.ps1`. |
| `python/samples/device-code-bootstrap/device_code_bootstrap.py` | `python/samples/entra/invoke_entra_device_code_bootstrap.py` | Explicit Entra delegated bootstrap. |
| *(new)* | `python/samples/okta/passkey-login/invoke_okta_passkey_login.py` | Python counterpart to the working Okta login script. |
| *(new)* | `python/samples/okta/test_okta_myaccount_webauthn.py` | Python counterpart to the MyAccount smoke test. |
| *(new)* | `python/samples/okta/passkey-register/register_okta_passkey_via_idx_session.py` | Python counterpart to IDX registration handoff. |
| *(new)* | `python/samples/okta/passkey-login/test_okta_passkey_login_via_idx_session.py` | Python counterpart to IDX login handoff. |
| `scripts/validation/submit_queue_passkey_registration.py` | `scripts/validation/submit_entra_queue_passkey_registration.py` | The queue contract currently targets Entra ESTSAUTH. |

### Automation, validation, and copied host assets

| Former path | Current path | Reason |
| --- | --- | --- |
| `azure-automation/function-passkey-runbooks/LoginWithPasskey.Runbook.ps1` | `azure-automation/function-passkey-runbooks/LoginWithEntraPasskey.Runbook.ps1` | Runbook calls the Entra-backed Function login endpoint. |
| `azure-automation/function-passkey-runbooks/RegisterPasskeyViaEstsAuth.Runbook.ps1` | `azure-automation/function-passkey-runbooks/RegisterEntraPasskeyViaEstsAuth.Runbook.ps1` | Runbook submits an Entra ESTSAUTH registration request. |
| `azure-automation/function-passkey-runbooks/RegisterPasskeyViaTap.Runbook.ps1` | `azure-automation/function-passkey-runbooks/RegisterEntraPasskeyViaTap.Runbook.ps1` | Runbook submits an Entra TAP registration request. |
| `scripts/validation/Invoke-PasskeySmokeTest.ps1` | `scripts/validation/Invoke-EntraPasskeySmokeTest.ps1` | Smoke test exercises the Entra local and hosted paths. |
| `scripts/validation/Invoke-QueuePasskeyRegistration.ps1` | `scripts/validation/Invoke-EntraQueuePasskeyRegistration.ps1` | Queue client targets Entra ESTSAUTH. |
| `scripts/validation/Invoke-LiveFunctionQueueValidation.ps1` | `scripts/validation/Invoke-EntraLiveFunctionQueueValidation.ps1` | Live validation targets the Entra Function samples. |
| `function-app/powershell/keyvault-passkey-http/scripts/Sync-PasskeyAssets.ps1` | *(no change)* | Shared host utility copies the provider-specific Entra and Okta assets into the PowerShell Function package. |
| `function-app/python/keyvault-passkey-http/scripts/Sync-PasskeyLibrary.ps1` | *(no change)* | Shared host utility copies the Entra and Okta library into the Python Function package. |
| `function-app/powershell/keyvault-passkey-http/src/shared/passkey-assets/scripts/Register-KeyVaultPasskey.ps1` | `.../scripts/entra/Register-EntraKeyVaultPasskey.ps1` | Copied canonical Entra registration wrapper; kept aligned by the sync script. |

## Contract-sensitive host paths

Function trigger directories, `run.ps1`, and `function_app.py` are deployment/runtime
names, not just sample filenames. The directories, internal function names, and HTTP
routes now carry the provider:

| Current logical surface | Proposed provider-explicit surface | Migration requirement |
| --- | --- | --- |
| `function-app/**/src/LoginWithPasskey` | `LoginWithEntraPasskey` | Route: `/api/entra/passkeys/login`. |
| `function-app/**/src/RegisterPasskeyViaTap` | `RegisterEntraPasskeyViaTap` | Route: `/api/entra/passkeys/register/tap`. |
| `function-app/**/src/RegisterPasskeyViaEstsAuth` | `RegisterEntraPasskeyViaEstsAuth` | Route: `/api/entra/passkeys/register/estsauth`. |
| `function-app/**/src/QueuePasskeyRegistrationViaEstsAuth` | `QueueEntraPasskeyRegistrationViaEstsAuth` | Queue route: `/api/entra/passkeys/register/estsauth/queue`. |
| `function-app/**/src/ProcessPasskeyRegistrationViaEstsAuth` | `ProcessEntraPasskeyRegistrationViaEstsAuth` | Queue trigger remains bound to the same queue. |
| `function-app/**/src/GetPasskeyRegistrationStatus` | `GetEntraPasskeyRegistrationStatus` | Status route: `/api/entra/passkeys/register/status/{requestId}`. |
| `function-app/python/**/src/function_app.py` | *(keep filename)* | Azure Functions Python discovery expects this host entry point. |

The same provider-explicit names should be used for Azure Automation runbooks and Logic
App workflow display names, but those are deployment artifacts and should be changed in
the same release as their callers.

## Shared library rule

Do not add `Entra` or `Okta` to genuinely shared WebAuthn, encoding, sync, or Key Vault helper
modules. Provider-specific implementations should carry the provider name; shared
contracts and helpers should remain provider-neutral. The canonical Entra implementations
now use `entra_login.py` and `entra_registration.py`. The mirrored Function App package
should continue to be generated from the canonical library rather than renamed independently.
