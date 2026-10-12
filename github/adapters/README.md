# GitHub secret adapters

Maintained functions live in `powershell/src/GitHub`, with enrollment using the shared
Entra registration flow. The files here are generated, self-contained distributions.
GitHub provides secret storage and CI transport; it is not a cryptographic signer.

See the [usage/build guide](../../powershell/BUILD.md) and [Action package](../action-passkey-login/README.md).

`Register-GitHubPasskeyViaTAP.ps1` warns about software limitations and non-atomic
secret updates. It verifies the expected registration before
export. `Export-PasskeyToGitHubSecret.ps1` can be dot-sourced to load functions, or
invoked with an explicit credential and repository. Four secret writes are not atomic;
private-key secret is written last. Inspect any partial failure before resuming consumers.
Use `-WhatIf` for no-I/O validation. No real credential is used by the offline tests.

## TAP enrollment preflight and result

Use a short display name such as `TokenForge 261011` (17 characters). The current public
My Sign-ins passkey-name field limits names to 30 characters; these commands reject blank
or longer names before authentication/enrollment. This does not establish why any earlier
attempt failed. Source: [My Sign-ins](https://mysignins.microsoft.com/security-info), app
4.0.2289, [public JavaScript bundle](https://mysignins.microsoft.com/bundle/main.e79f2476.js).

```powershell
Register-GitHubPasskeyViaTAP -TAP $tap -UserPrincipalName 'user@example.com' `
    -Repository 'owner/repo' -DisplayName 'TokenForge 261011'
```

`TenantId` is optional for UPN-based TAP flows. Public Microsoft OIDC metadata resolves the
UPN suffix to a tenant GUID; no redirects are followed and the issuer must be the exact
Microsoft HTTPS GUID issuer. Use `-TenantId '<tenant-guid>'` for a different intended guest
or resource tenant. Discovery does not prove which tenant you intend. Token client/tenant/user
binding remains mandatory. ESTS-cookie flows use the authenticated identity instead.

Pause or disable consumers yourself before confirming: the command does not pause them.
Four writes are non-atomic, metadata first and private key last. No rollback is available.
A failed export reports confirmed names and the failed or uncertain current name. Resume
consumers only after a complete verified export. `Success` is returned only after all four writes.

Failures expose a safe `TargetObject` with `Code`, `Stage`, `EnrollmentStatus`, `ExportStatus`,
`ConfirmedWrites` and `FailedOrUnknownSecret`. Authorization-continuation failures also expose
`FailureCategory`, `HttpStatus`, `ServiceErrorCode`, `AadstsCode`, `ContinuationPage` and
`MissingField` when available. Print only these safe fields if a handoff catches errors;
do not replace them with `NOT_CONFIRMED` or print raw exception/response bodies.
`NotStarted` means this operation has not submitted a credential; `Unconfirmed` means a
submission may have enrolled it; `Verified` means exact credential-ID verification succeeded.
Preflight/authentication failures do not imply partial enrollment. Never retry an unconfirmed
enrollment automatically. Check My Sign-ins first. No TAP, cookie, token or private key is included.

Known KMSI continuation supports quoted or unquoted HTML attributes and the existing
config-driven `KmsiInterrupt` payload only when no form starts exist and all required
fields are scalar strings. A config-less page can continue a single, complete hidden-only
form to the exact Microsoft login `/kmsi` authentication target, with no query or fragment.
Other config-less targets, consent/policy pages, malformed forms and mismatched callback
state remain refused. A returned sign-in page alone does
not identify the cause. TAP expiration or prior one-time use can prevent authorization;
the [Microsoft TAP guide](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass)
documents a default one-hour lifetime, but the tenant's configured lifetime may differ.

The no-redirect transport captures PowerShell 7.6's expected `MaximumRedirectExceeded`
record only alongside an actual redirect response. It follows no redirects automatically,
preserves session cookies, still fails all other transport errors and does not retain the
captured request error in the caller's error history.
