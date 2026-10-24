# Fork-safe live validation plan

Status: the bounded [cookie-contract controller](LAB-COOKIE-CONTROLLER.md) is prepared in source; independent live readback remains unimplemented. No Azure federation, role assignment, environment protection, enrollment, live login or workflow enablement is established by these files. Source-only/offline checks are not live validation. Use only the new environment-only `PASSKEY_LAB_*` names for this protected lane; never provision legacy repository-secret names for it.

## Preferred first lane: approved lab passkey secrets

The selected first live test uses a dedicated generic lab user and passkey values in GitHub secrets. Use four encrypted secrets in the protected `passkey-validation` environment, matching the existing private-key workflow inputs:

- `PASSKEY_LAB_CREDENTIAL_ID` -> `credential-id`
- `PASSKEY_LAB_USER_HANDLE` -> `user-handle`
- `PASSKEY_LAB_USER_PRINCIPAL_NAME` -> `user-principal-name`
- `PASSKEY_LAB_PRIVATE_KEY` -> `private-key` (PEM or supported encoded form)

Use a dedicated minimally privileged lab account and passkey, not a personal administrator credential. This lane does not need Azure Login, a federated workload identity, Key Vault access, or `id-token: write`. The old manual private-key example is disabled at this revision. The new controller supplies protected-environment admission, exact-SHA review and safe output transport, but independent readback remains unimplemented.

A workflow that receives the private key can exfiltrate or reuse it. GitHub encryption at rest and log masking do not protect against malicious admitted code. Fork PRs must remain offline-only. Approve the exact candidate revision before releasing the environment secrets; do not enable automatic live runs.

The user enters values directly through GitHub encrypted environment-secret controls or a separately approved secure local workflow, never chat, source files, patches or artifacts. The stated preference does not itself configure or authorize transmission of a key. Explicit approval is required for the specific account enrollment, sensitive key transmission/storage destination, environment permissions, and bounded first live run.

## Outcome and trust boundaries

The selected first implementation is local signing with encrypted GitHub environment secrets for a generic, dedicated, minimally privileged test user. No Azure workload identity, federation, Key Vault, Azure role assignment or OIDC permission is required for this lane.

The account is intended to have no useful access. Verify its actual memberships, licenses, assignments, application consent and tenant-default capabilities; do not claim a basic account can have literally no access. Do not add broad roles, weaken tenant policy or grant broad consent to make a test pass. A required interaction or policy refusal is a reported validation blocker.

Keep required offline tests on every PR. Fork PRs must not receive the test environment or private key. A workflow condition is defense in depth; protected-environment controls and immutable code admission are also required. Keep this experimental software flow distinct from certified authenticator guarantees.

Configure the `passkey-validation` environment with a required reviewer and selected deployment branch `main`, and disallow bypass where supported. Reviewers approve the exact immutable candidate, not a mutable PR branch. A copied fork does not inherit these environment secrets. Do not use "protected branches only" without verifying protection exists; GitHub documents that absent branch protection can permit every branch.

## Milestone 1: source and offline preparation

- Keep the current offline PR checks credential-free and required.
- Implement a trusted controller workflow and tests, initially manual and unavailable until configuration is approved.
- Missing configuration is `not configured/not run`, never a live pass.
- Use environment variables for dynamic action outputs and inputs; never interpolate expressions into PowerShell source.
- Test repository/ref guards, immutable SHA admission, permissions, configuration completeness, sanitized receipts and negative paths.
- Keep output-contract validation distinct from independent session usability and XDR access.
- Make source changes in research-passkeys and distribute the reviewed action subtree; record both source and distribution revisions.

Exit: reviewed code and passing offline tests, with live status explicitly unverified.

## Milestone 2: explicit test account and GitHub configuration

Use the dedicated generic test account and a passkey enrolled specifically for this validation. Verify its actual effective privileges and avoid unrelated user or administrator credentials.

Required approvals and setup before execution:

1. Confirm the test account, passkey enrollment and any narrowly necessary consent. No broad consent, tenant-policy bypass or role grants.
2. Configure the protected `passkey-validation` environment and its reviewer/branch controls.
3. Obtain explicit approval for transmitting/storing `PASSKEY_LAB_PRIVATE_KEY` and the three other named values in that encrypted environment-secret destination. The user enters the key directly in GitHub, never chat or Git source.
4. Approve the first bounded live login/readback for the exact reviewed revision and test account. The present preference does not perform any of these actions.

Exit: verified four-secret/environment configuration and test-account scope, without a claim of successful login yet.

## Milestone 3: trusted exact-revision live validation

Use `workflow_dispatch` on trusted main initially. Do not execute untrusted candidate code using `pull_request_target` or a privileged `workflow_run` chain.

1. In an unprivileged preflight, verify a full candidate SHA, expected repository, PR/head relationship, source review and exact-SHA offline results. A mutable branch or PR number is not sufficient admission.
2. Record the immutable candidate and controller revisions for the environment reviewer. Recheck current candidate identity before access is released; a new revision requires new admission.
3. Require protected-environment approval before any candidate execution with the private key or private configuration.
4. Check out the exact candidate into a separate directory and verify its SHA. Disable persisted checkout credentials. Do not restore untrusted caches or candidate-built artifacts into the privileged job.
5. Use a disposable hosted runner, job-scoped `contents: read`, no `id-token: write`, pinned actions, a timeout, and serial test-account concurrency.
6. Run the reviewed candidate and validate its output contract from trusted controller code.
7. Independently exercise a reviewed, read-only authenticated endpoint with an explicit expected account/tenant and response schema. Select and review that endpoint before implementation; do not substitute arbitrary portal cookies for authentication evidence.
8. Emit an allowlisted receipt containing candidate SHA, source revision, controller SHA, run URL/time, runtime, scenario, and individual assertion outcomes. Do not trust candidate-generated summary content as independent validation.

The reviewed candidate can read or exfiltrate the private key released to its job, even when logs are masked. Environment approval is admission to that trust boundary, not a sandbox.

Current XDR helper limitation: even successful form exchange plus portal cookies proves only portal-bootstrap evidence. It does not prove authenticated XDR readback or tenant identity. The bounded bootstrap fix must not become an XDR-authentication badge.

Exit: first real receipt for the exact reviewed revision; negative tests must show no live pass on missing configuration, failed exchange, absent cookie or unsuccessful authenticated readback.

## Milestone 4: cleanup and honest publication

- Mask cookies before output; keep them in the narrowest process/step scope. Never log them or write them to artifacts, caches, summaries or cross-job outputs.
- Do not persist the private key or cookie beyond the job; remove temporary files with `always()` cleanup and discard the runner. Avoid cross-job secrets and privileged caches.
- Local cleanup does not revoke an Entra browser session or the registered passkey. Remove/revoke the dedicated test credential when retiring the setup; explicitly approve that separate change. Document that limitation; do not add broad Graph revocation permissions just for convenience.
- Publish separate Offline tests and Live lab validation signals. Live evidence includes exact SHA, timestamp, platform/scenario and freshness.
- Skipped, unconfigured, expired or stale evidence is not a live pass. The badge must link to the tested receipt, not imply current main was tested when only an older candidate passed.
- Do not claim FIDO certification, production suitability or untested platform/downstream support.
- Keep live runs as a maintainer admission/release gate initially. Later automation may cover trusted main or explicitly admitted revisions after the manual path is proven.

## Optional later alternative: Key Vault/OIDC

If desired later, retain the private key in a dedicated vault and let an Entra workload identity sign using GitHub OIDC. This is not a prerequisite or part of the first implementation. It adds Azure federation/RBAC setup requiring separate approval. The enrolled test user remains separate from that workload identity.

Bind trust to this repository and the protected environment using its verified actual OIDC subject, issuer `https://token.actions.githubusercontent.com`, and audience `api://AzureADTokenExchange`. Prefer immutable IDs when supported/configured; do not assume the subject format. Environment subjects require separate main-branch restrictions. Use minimum signing privileges and a versioned key. Retain Azure Login cleanup; it does not revoke user browser sessions. Follow the linked GitHub and Microsoft guidance when implementing that alternative.

## Official references checked 2026-10-23

- [GitHub OIDC claims and immutable subjects](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub deployment environments and protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub workflow events, fork restrictions and privileged-trigger warnings](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Microsoft Azure Login with OIDC](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect)
- [Microsoft Key Vault RBAC guidance](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [Azure Login cleanup behavior](https://github.com/Azure/login#enabledisable-the-cleanup-steps)
