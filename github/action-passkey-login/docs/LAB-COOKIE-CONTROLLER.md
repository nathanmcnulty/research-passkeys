# Protected lab session-reuse controller

Status: source preparation, not evidence of a live pass. Setup, publication,
controller bootstrap, hosted CI and live dispatch require their own authorization.

## Narrow success claim

The manual `validate-lab-cookie.yml` tests one exact reviewed Action revision. It
first checks the cookie-output contract, then reuses only that cookie in a fresh
silent authorization-code/PKCE transaction and calls Microsoft's UserInfo API.
Success means **server-backed session reuse verified for this reviewed candidate**.
It does not establish XDR access, effective token permissions, or hostile-code attestation.
The final job requires both preceding jobs to succeed; missing configuration,
policy/consent interaction, failed probes and skipped jobs cannot produce a pass.

The candidate receives the private key and can modify its runner, controller files,
subsequent steps and summaries. Exact-source review is the trust boundary. Same-runner
remote corroboration is an integration test, not a sandbox or tamper-proof evidence.
No cookie/token is transported between jobs or saved in artifacts/caches.

## Explicit client compatibility scenario

Select an exact reviewed public-client ID and verify that its registered mobile/desktop
callback is `https://login.microsoftonline.com/common/oauth2/nativeclient`. This first
bounded compatibility scenario can use the Action's familiar Azure CLI client
`04b07795-8ddb-461a-bbee-02f9e1bf7b46` with that documented callback. This is a research
compatibility test, not a Microsoft-endorsed integration: Azure CLI maintainers warn
that use of their ID outside Azure CLI is unsupported and may stop working.

The helper has no default client, no automatic client switching, and no borrowed
resource scopes. It requests only `openid profile`, never `.default`, `User.Read`,
`offline_access`, XDR or Azure permissions. Existing tenant policy, assignment and
consent must permit the selected scenario; consent/interaction errors stop the run.
No registration, grant, policy change or fallback is performed to make it pass.

Microsoft Graph Command Line Tools is a separate possible compatibility scenario,
not a reason to assume this fixed callback works for it. Review its exact callback
before selecting it; a loopback callback is not silently substituted or followed.
An owned public client is an alternative if desired, not a prerequisite imposed on
the user or every Action consumer. New registration/consent would need separate approval.
The test explicitly overrides `auth-url` and `expected-client-id`, leaving consumer
defaults unchanged. The protected workflow explicitly sets `confirm-application: 'true'`;
that reviewed opt-in does not change consumer defaults.

Set non-secret environment variables `PASSKEY_LAB_TENANT_ID` and
`PASSKEY_LAB_CLIENT_ID` in the protected `passkey-validation` environment only after
setup approval. No actual identifiers or test UPN belong in public source. The
expected current UPN comes from the existing lab UPN secret. The helper checks the
fresh ID token's tenant, issuer, client audience, nonce, times, valid object ID and
current UPN; UserInfo's subject must match that ID token. UPN can change or be
reassigned: this is not an immutable account pin across runs. No identity values
are included in the public result summary.

## Protocol and transport boundaries

`LabSessionProbe.ps1` is a deliberately small test helper, not an authentication SDK.
It creates fresh random state, nonce and PKCE S256 values; requests only `openid
profile` with `prompt=none`; intercepts the exact callback without visiting it; and
fails on interactive pages, malformed callbacks or unexpected redirects. No TAP,
password, private key, saved token or ambient authentication is available to the probe.

Discovery is tenant-specific and endpoints must match the expected Microsoft HTTPS
origins/paths exactly. Token and UserInfo redirects are rejected. Native HttpClient
uses normal certificate validation, no proxy, automatic redirects, default credentials
or cookie jar. Responses are bounded to 64 KiB and timed out. Errors suppress server
bodies, request values and token material.

ID tokens are accepted **only from the helper's direct authenticated TLS token-endpoint
response**, never from candidate outputs, caches, files or redirects. OIDC Core
3.1.3.7(6) permits TLS server validation in place of signature verification for that
specific code-flow response. All other claim checks remain mandatory. This is not
a generic JWT-signature validator and cannot authenticate arbitrary supplied tokens.
Access tokens are used only at the discovered, allowlisted UserInfo endpoint; their
permissions are not an acceptance criterion. The requested `openid profile` scopes
do not promise that returned permissions match that list. An optional returned
`scope` must be a nonempty string with RFC 6749 scope syntax, but permission names
are not allowlisted. Its omission is permitted. No refresh token is requested or retained. Memory references are cleared
best-effort; managed strings are not guaranteed to be zeroized.

## Optional local scope observations

The [scope-observation contract](LAB-COOKIE-SCOPES.md) separates requested scopes,
returned `scope` and locally decoded, **unverified** access-token `scp`. The helper
can optionally populate a caller-owned in-memory container only after every ID-token
and UserInfo acceptance check succeeds. The default path does not decode access
tokens and emits exactly the same Boolean success receipt. No current workflow opts
in; no observation is logged, published, written to a workflow output or exported.

The returned permission-name allowlist was intentionally removed. Protocol syntax
validation remains; narrow observation formatting and size limits are not new
authentication requirements. Opaque, unsupported or malformed diagnostic JWTs simply
have unavailable observations. Names can vary between responses and do not prove
consent, effective authority or access to any API. A future export needs a separately
reviewed destination and audience; this helper provides no export mechanism.

## Bootstrap and exact admission

1. Review controller workflow, `LabController.ps1`, `LabSessionProbe.ps1` and tests.
   A separately authorized controller-only main change must install those files.
   Do not merge the entire unvalidated Action candidate as a bootstrap shortcut.
2. Review and publish canonical source, obtain exact-revision offline CI, then merge
   canonical source only when authorized. The source revision must belong to canonical
   main. Mirror the entire Action subtree exactly to the candidate PR.
3. The existing `passkey-validation` environment must have required reviewers and
   exactly one selected deployment policy, branch `main`, not tags/wildcards or only
   protected branches. Disable bypass where supported. Preflight reads these rules
   before the protected job and rechecks them after approval.
4. Use only the four environment secrets `PASSKEY_LAB_CREDENTIAL_ID`,
   `PASSKEY_LAB_USER_HANDLE`, `PASSKEY_LAB_USER_PRINCIPAL_NAME`, `PASSKEY_LAB_PRIVATE_KEY`.
   Verify there is no same-name repository/organization fallback. Do not populate old
   `PASSKEY_PRIVATE_*` names; old workflow revisions are not revoked by this change.
5. Approve one bounded dispatch for exact candidate/source/controller SHAs and the
   disposable account/application. Review those revisions before releasing environment
   secrets. Reruns are rejected. Main/PR movement requires a fresh reviewed dispatch.

The latest exact-SHA push CI attempt must pass in both repositories, using pinned
offline workflow blobs. `[skip ci]` publication alone cannot satisfy this. Hosted CI
needs separate authorization when previously excluded. No automatic live trigger,
GitHub federation, Key Vault or `id-token: write` is introduced. Cleanup removes
checkouts; it does not revoke remote sessions or the passkey. Revocation is separate.

## Sanitized failure diagnostics

A failed session probe remains a failed validation. Its public error includes only
fixed, locally assigned and allowlisted phase/category/predicate tuples, never the original
exception text, URLs, response headers/bodies, identity claims or credential values.
Unknown labels/types/combinations use a fixed fallback rather than reflecting external data.
The [complete predicate inventory and coverage contract](LAB-COOKIE-PREDICATES.md)
distinguishes first-rejecting checks from entered operations and explains cleanup
failure precedence. `TransportFailure` is a bounded category, not a root-cause claim.

The phase identifies the operation or guard entered, not proof that a network
request reached Microsoft. A rejection code identifies a local acceptance boundary;
it is not by itself evidence of a service defect, an invalid credential or a consent
requirement. Diagnostics do not relax protocol checks or authorize a retry. Older
runs that emitted only the generic failure cannot be retroactively diagnosed from
these new codes. Successful receipts and request sequencing are unchanged. The intentional returned-scope
policy change is documented separately; it is not described as diagnostic-only.

## Sources

- [Microsoft UserInfo and identity-only permissions](https://learn.microsoft.com/en-us/entra/identity-platform/userinfo)
- [Microsoft authorization code flow and PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [OIDC direct token-response validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
- [Microsoft identity claims and mutable usernames](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
- [Azure CLI's client ID is not supported for other applications](https://github.com/Azure/azure-cli/issues/23256)
