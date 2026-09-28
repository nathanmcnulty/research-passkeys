# Research passkeys roadmap

Reviewed 2026-09-12 against local commit `1e7975185624a85a872e413901b1c1dde10f921e`. This is an execution plan, not new deployed validation. Provider integration and the shared milestone sequence are in the [provider roadmap](../key-vault-passkey-provider/plans/project-roadmap.md).

## Role of this project

Own shared contracts, independent reference implementations, reusable validation fixtures, and carefully scoped Azure/Entra/Okta experiments. Keep Windows provider integration in its existing repository. Choose one production broker implementation home/language after contract review; do not turn every sample into a supported production service.

Prioritize one reproducible deployed reference path, then parity and production hardening. A successful research enrollment that synthesizes authenticator behavior does not establish a trustworthy authenticator or genuine UP/UV.

## Evidence and documentation reconciliation

| Area | Current evidence | Remaining work |
| --- | --- | --- |
| Browser/Function assertion is deliberately unavailable | Python `function_app.py`, `assert_with_stored_passkey_http`, returns 501; browser `function-catalog-client.ts` rejects before network; PowerShell also fails closed | Preserve denial until trusted fresh user-presence/proof exists; checked POC assertion wording in browser TODO is stale |
| Registration through extension | Current POC falls back to native registration | Broker reservation/finalization/abort protocol; do not claim broker registration is implemented |
| Counter concurrency | Python has ETag-capable storage helpers; active assertion/counter advancement is not established because the endpoint is disabled | Executable conflict/retry tests once the proof-gated operation exists; do not reuse old POC claims as runtime evidence |
| HTTP Function authentication | Both Function Bicep sources configure Easy Auth issuer/audience/calling application; application code has caller identity and owner filtering | Verify effective deployed controls and complete the authorization/delegation contract; authentication is not wholly unimplemented |
| Queue authentication mismatch | Bicep globally requires authentication with no excludedPaths, while browser docs describe key-only queue ingress outside Easy Auth | Prove actual route behavior, then choose/document the intended policy before changing exclusions |
| Shared tests | Reviewer reran `python -m unittest discover -s function-app/tests -p 'test_*.py' -v`: 32 passed on 2026-09-12; suites are primarily contract/source-shape checks | Add runtime cryptographic/HTTP evidence; these tests do not prove deployed behavior or RP acceptance; Pester was not rerun in this review |
| Operational examples | Existing scripts include credential-creating, queue, TAP/session, and device-code examples | Do not run a broad sample suite as a read-only check. Use cached WAM/MSAL or normal browser authentication; device-code flows are excluded from this work |

Beyond the refreshed 32 Python tests, historical build/test results should be refreshed before implementation. This roadmap review did not run live authentication, deploy Functions, submit queues, create credentials, or change tenant policy.

## R1A: reproducible local baseline

Suggested effort: 1–2 days. Owner: reference implementation contributor. No live credentials required.

1. Record repository commit, Python/PowerShell/Node versions, dependency manifests, and current working-tree state. Establish isolated dependencies and resolve imports, including token-inspector dependencies, before interpreting a smoke-test failure as a product bug.
2. Run the existing Function contract tests with Python unittest discovery against `function-app/tests`, the focused Pester broker suite, and the extension's declared adapter validation/build commands. Inspect scripts before invoking them; do not run similarly named live Okta scripts during offline discovery.
3. Verify canonical Python library and deployable Function copies using the existing `function-app/python/keyvault-passkey-http/scripts/Sync-PasskeyLibrary.ps1` workflow when a source change requires refresh. Inspect drift first; do not blindly rewrite deployable copies during review.
4. Inventory the selected deployment profile and its generated settings: Easy Auth, issuer/audience/calling application, exact excluded Queue routes, function-key requirements, storage authorization, Key Vault access, network settings, and telemetry.
5. Reconcile the conflicting TODO statements using a table of source implemented / locally tested / deployed verified / still pending. Keep profile-specific gaps visible rather than checking all authentication work complete.

Exit: reproducible commands and results tied to one commit; source-copy parity established; each auth route/profile has a known status. Historical green tests are not sufficient.

## R1B: deployed Function baseline

Suggested effort: 2–4 days after test environment/access is ready. Owner: deployment/test contributor. Requires a selected existing lab target, one test identity, and authorization for the specific deployment or test writes.

Start with Python's catalog/owner boundary and deliberate assertion denial as one proposed reference. Run deployment what-if and inspect the exact lab changes before an authorized deployment. A successful hosted assertion depends on B1 and a trustworthy fresh-presence/proof channel; do not remove the 501/native-proof guard merely to obtain a demo. This sequencing does not select the production broker language.

| Test | Expected result |
| --- | --- |
| Anonymous catalog/assertion | Authentication denial; no key use or record disclosure |
| Wrong issuer/tenant/audience/calling application | Denied by the intended boundary, including direct endpoint access |
| Correct authenticated identity, another caller's record | Denied server-side; catalog filtering is not sufficient authorization |
| Correct caller, wrong RP/credential association | Denied before signing |
| Queue Function key only, then Entra identity plus required key | Record actual global Easy Auth behavior; resolve the docs/source mismatch, preserving catalog/assertion authentication |
| Authorized active test record in current assertion endpoint | HTTP 501 and no signing; browser blocks before network; do not interpret this expected denial as a regression |
| Catalog or direct record access under a second caller | Owner isolation and no-store behavior verified independently of disabled assertions |
| Future proof-gated assertions: inactive record, stale cache, counter conflicts, ambiguous timeout | After B1/proof integration, verify rejection and conditional retry behavior without state rollback or cross-request result reuse |
| Malformed/oversized request or upstream exception | Stable redacted error and correlation ID; no raw session/provider payload |

Capture deployed artifact/config identity, request IDs, sanitized responses, before/after record versions, and relevant Key Vault data-plane logs where enabled. Exercise existing owner checks through every relevant route and define missing delegation behavior before expanding exposure; catalog filtering alone does not close authorization.

## R2: Entra and Okta evidence matrix

Suggested effort: 2–5 days per selected scenario, with platform/policy blockers tracked separately. Depends on R1 and trusted UV support wherever the relying party requires it.

Use one target RP and one flow at a time. First classify which local/hosted operations are deliberately disabled for lack of trusted UP/UV; such a cell remains blocked until the required trusted path exists. Existing Entra smoke-test and live queue validation scripts are starting points to inspect, not commands to run blindly: they accept TAPs/session material and can create credentials. Keep sensitive results disabled and pass secrets through protected inputs, never URLs or committed artifacts. Never initiate device-code authentication, including indirectly through a sample wrapper. Keep ESTSAUTH/session-cookie paths compatibility-only and plan replacement/quarantine of device-code starter guidance.

| Stage | Scope | Completion evidence |
| --- | --- | --- |
| R2.1 | Python local reference on one selected Entra or Okta test account | Actual registration acceptance and subsequent login, with policy/capability classification |
| R2.2 | Selected hosted Entra TAP/ESTSAUTH registration/login compatibility flow | RP acceptance experiments may proceed where the selected flow does not require trusted UP/UV; these are not production authenticator proof. Browser/Function assertion remains deliberately denied until B1/trusted proof integration |
| R2.3 | PowerShell equivalent against matching fixture/scenario | Equivalent allowed/denied behavior, including concurrency; intentional differences documented |
| R2.4 | Second RP family and required-UV cases | Accepted trusted flow or exact unsupported policy requirement; no fabricated UP/UV/attestation |
| R2.5 | Queue/runbook/Logic App adapter, only if needed | End-to-end job result, safe retry and poison handling; queue acceptance alone is insufficient |

For each cell record implementation, direct/hosted mode, RP policy, test account alias, credential/proof type, expected result, actual result, evidence, and cleanup disposition. Distinguish RP-policy rejection from serialization/signature defects. A research reference result does not transfer automatically to the native Windows provider.

## B0/B1: shared broker contract contribution

Dependencies: R1 inventory plus the first native provider lessons. Suggested effort: 2–3 days for contract/fixtures, followed by the implementation estimate in the provider roadmap.

1. Put versioned operation/record/error/proof schemas and lifecycle fixtures in `contracts/`. Choose who constructs authenticator data and what trustworthy origin/UP/UV evidence it consumes.
2. Resolve two old TODO assumptions before implementation: browser-local PIN cannot authorize truthful UV, and raw Key Vault key identifiers should remain internal to the production broker. Return opaque credential/reservation references plus required public material.
3. Specify reserve/create, finalize, abort, discover, assert, disable/delete, and reconcile behavior. Define how finalize learns RP acceptance; an authenticator cannot universally observe the RP's server-side result. Where no trusted callback exists, document the client signal's limitations and cleanup policy rather than claiming independently verified RP enrollment.
4. Define owner/delegate authorization, tenant boundaries, scoped idempotency/request hashes, conditional lifecycle/counter updates, one-use proofs, stale-cache rejection, and tombstone/offline retention.
5. Add executable cross-language fixtures for replay, changed request under one idempotency key, unknown ownership, counter races, crash after remote side effect, and delete/restore races. Structural source tests remain supplemental.
6. Select one canonical production implementation and build one complete lifecycle. Reference implementations consume the same contract; do not let their schema variants silently diverge.

Exit: one reviewable contract and threat model, with expected state after each failure. No generic digest-signing endpoint, client-asserted UV, or caller-selected Key Vault target.

## R3: operational hardening before broader deployment

Suggested effort: 1–2 weeks, sized again after selecting the supported hosted surface.

1. Reject reusable authentication artifacts in query strings; add body/header handling tests across HTTP, queue, runbook, and Logic App entry points. Verify poison queues and telemetry cannot retain replayable credentials, and define bounded retention/cleanup. Include encrypted durable login-context secrets: encryption does not supply expiry or lifecycle cleanup.
2. Replace raw exceptions with stable error codes/correlation IDs. Verify redaction for upstream response bodies, request logs, and failure telemetry.
3. Validate host admin isolation, disabled publishing/debug surfaces, payload limits, and CORS against actual deployment tooling. Add caller-aware rate/abuse controls before broad exposure.
4. Make dependency installation reproducible; run dependency/secret/IaC scanning and validate infrastructure changes in a selected lab. Inventory existing controls first to avoid duplicate work.
5. Measure whether private endpoints/DNS and a policy edge are needed for the selected threat model. Plan/test connectivity and rollback before migrating an existing service-endpoint profile.
6. Establish alerts for denied signing, unusual volume, deletion, authorization failures, and reconciliation/poison backlog. Verify actual alert delivery to the selected destination when that test is authorized.
7. Validate Premium/HSM requirements against the actual key type and service configuration. HSM custody does not repair untrusted authenticator assertions or inadequate broker authorization.

Exit: deployment/recovery runbook, effective identity/network controls, fault and abuse evidence, reproducible artifact, and tested observability. Keep unsupported samples explicitly research-only.

## Immediate work packages

| Order | Deliverable | Acceptance |
| --- | --- | --- |
| 1 | Route/profile authentication inventory and TODO reconciliation | Contradictory Easy Auth status resolved per deployed/profile scope, without erasing open ownership work |
| 2 | Fresh offline reference baseline | Tests/imports/source parity recorded against the exact commit |
| 3 | One deployed Python catalog/authentication experiment | R1B evidence, including cross-caller denial, queue auth behavior, and expected assertion 501 |
| 4 | Versioned broker contract and executable fixtures | One state/proof model shared with the provider; production implementation owner chosen |
| 5 | PowerShell parity and selected Entra/Okta proof | Executable behavior comparison and real RP outcome, with unsupported UV/policy cells clearly blocked |

Track owner, dependency, estimate, status, evidence, and next action per package. Keep status `planned` until execution starts. Leave product-code changes, tenant operations, external publication, and test-object cleanup to explicitly scoped execution sessions.
