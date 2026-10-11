# Login hardening and compatibility

## Changes

- Validate credential object types and resolved inputs before network activity. Existing username, RP, private-key and counter aliases remain supported; counters accept the full uint32 range.
- Limit Key Vault bearer-token destinations to validated HTTPS public-Azure vault key URLs. Reject conflicting metadata and prohibit signing redirects. Preserve a stored key version rather than silently changing to the latest version.
- Use the correct BSTR conversion and free its unmanaged buffer for SecureString tokens. Suppress server bodies and exception details that might echo authentication material.
- Require a nonempty, secure, unexpired ESTS cookie from an exact trusted Microsoft login domain before reporting success.
- Initialize interrupt state, bound repeated ConvergedSignIn, validate its initial destination, and safely encode the session identifier. Reject ambiguous decoded client IDs for explicit application confirmation.

## Caller review

Malformed/null credential properties, conflicting Key Vault metadata, nonstandard ports, malformed versions, and sovereign-cloud vault endpoints now fail closed. Correct the metadata; do not strip a stored version to bypass validation.

Unversioned manual key names remain accepted for compatibility and still select the current version. They are not rotation-safe. Prefer a versioned key URL in the existing `key-vault-key-name` input, or retain the versioned `keyVault.keyId` when calling the script with a credential file.

Action input/output names and the explicit cookie-export setting are unchanged. Direct script callers must request `-PassThru -IncludeAuthenticationCookie` to receive the cookie value, or explicitly opt into `-PersistSessionToGlobalScope` for in-process session retention. Never log or persist the returned cookie object. A missing trusted session cookie returns `Success = false`; callers must check it.

Application confirmation remains denied by default. `-ConfirmApplication` requires the expected authorization client exactly once; this does not grant OAuth permission consent. ESTS cookies are not OAuth access tokens and do not populate Azure CLI or Graph token caches.

## Verification and remaining limits

The offline Pester suite covers hostile Key Vault references, exact-version signing, redirect refusal, credential types, SecureString conversion, cookie selection/output, authorization URL validation and interrupt control flow. Run `Invoke-Pester ./tests -PassThru` with PowerShell 7 and Pester. The publication-time local run passed 43 tests using PowerShell 7.6.6 and Pester 6.2.0; hosted CI uses its separately pinned Pester version.

No live Entra or Key Vault authentication was performed for this update. Offline tests establish client-side behavior only. General login redirect handling has not been comprehensively redesigned or live-certified.

The existing software-signing path still asserts UP/UV without fresh authenticator-bound evidence. Key Vault protects the signing key but does not establish user presence or verification. This patch does not make the implementation a compliant authenticator or remove Conditional Access requirements. Registration/attestation and broker/token redesign are outside this change.
