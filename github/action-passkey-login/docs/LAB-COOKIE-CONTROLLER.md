# Protected lab cookie-contract controller

Status: source preparation only. Nothing here configures an account, GitHub
environment or secret, publishes a controller, or authorizes a live dispatch.
Independent session/identity readback is **not implemented**.

## What this lane proves

`validate-lab-cookie.yml` admits one reviewed exact Action PR head and observes its
cookie-output contract. A successful contract step is not independent proof of
authentication, account/tenant identity, session usability or XDR access. The UPN
output is copied from input. A separate credential-free final job deliberately
fails every run until independent readback is implemented and reviewed. Do not
make that intentional-incomplete workflow a required PR check or a green badge.

The current candidate still uses its existing Azure CLI client and Graph `.default`
authorization URL. This controller does not change that bootstrap or assume the
client grants resource access. Application confirmation is explicitly false;
consent, interaction and policy refusals are blockers, not invitations to grant
permissions. There is no token exchange, proxy override, custom authorization URL,
Key Vault, GitHub federation or `id-token: write` in this lane.

## Bootstrap and admission

1. Review this controller and its tests separately. Publish only the reviewed
   controller workflow and `.github/validation/LabController.ps1` to distribution
   main through a separately authorized controller-only change. This source packet
   does not perform that merge. Existing offline CI remains credential-free.
2. Publish canonical source changes and obtain their offline CI/review first.
   Mirror the exact `github/action-passkey-login` subtree to the candidate Action
   PR. The preflight requires that source revision already belong to canonical
   main and that its subtree tree hash equal the entire candidate root tree hash.
3. Before storing credentials, configure the existing `passkey-validation`
   environment with required reviewers and exactly one selected deployment policy:
   branch `main`, not a tag/pattern or “protected branches only.” Disable bypass
   where supported. The controller reads and checks these settings before the
   environment job and again after approval; unreadable/missing settings fail.
4. Use only a dedicated, minimally privileged disposable lab account. Verify its
   actual effective access. Never grant broad access or weaken policy to pass.
   Registration and storage require separate specific authorization.
5. Store only these new **environment-only** secrets in `passkey-validation`:
   `PASSKEY_LAB_CREDENTIAL_ID`, `PASSKEY_LAB_USER_HANDLE`,
   `PASSKEY_LAB_USER_PRINCIPAL_NAME`, `PASSKEY_LAB_PRIVATE_KEY`.
   Verify that no same-name repository or organization secret supplies a fallback.
   Do not populate `PASSKEY_PRIVATE_*` for this lane. The old private-key example
   is disabled at this revision, but old branches and reruns retain old workflow
   code. New names prevent that old code from requesting the lab credential.
6. After exact-run authorization, dispatch current main with full `candidate_sha`,
   `source_sha` and the same-repository Action `pull_request` number. Review the
   immutable revisions in preflight before approving the environment. Reruns are
   rejected. Main or PR movement requires a fresh dispatch and review.

Preflight requires the latest push-run attempt at each exact SHA to have completed
successfully, and pins the offline workflow file hashes. A workflow change needs
a separate controller review. CI is not a substitute for human source approval.
Do not edit code in only the distribution repository.

## Trust and outputs

The admitted candidate receives the private key and can exfiltrate it or alter its
runner, including controller files, subsequent steps and summaries. Separate
directories, masking and step-scoped environment variables reduce accidental
leaks; they do not sandbox hostile code. Approval is admission to that boundary.
Controller-generated contract observations are not tamper-proof independent
evidence. The immutable admission summary is created before candidate execution.

No cookie or credential is intentionally placed in artifacts, caches, summaries
or cross-job outputs. Each live run uses a disposable hosted runner, timeout and
serial account concurrency. Cleanup discards checkouts, but does not revoke remote
sessions or the enrolled passkey. Retirement/revocation is a separate authorized
operation. Never send a private key or TAP in chat.

## Deferred independent probe

Microsoft's documented UserInfo endpoint is a bearer-token API, not a cookie-only
endpoint. An optional future probe could use a separately reviewed existing public
client and registered callback, silent code/PKCE, `openid profile`, validated fresh
ID token and UserInfo subject match. No compatible client/callback or approved
token-validation library is established here. Do not assume a Microsoft first-party
client permits arbitrary redirects/scopes. New registration or consent requires
separate approval. No `.default`, `User.Read`, `offline_access`, broad permission
or automatic consent should be added to that probe merely to make a test pass.

References: [Microsoft UserInfo](https://learn.microsoft.com/en-us/entra/identity-platform/userinfo),
[GitHub environments](https://docs.github.com/en/rest/deployments/environments),
[GitHub branch policies](https://docs.github.com/en/rest/deployments/branch-policies).
