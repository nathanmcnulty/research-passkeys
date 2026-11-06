# Session-probe predicate diagnostics

This describes the fixed diagnostic labels for [`LabSessionProbe.ps1`](../.github/validation/LabSessionProbe.ps1). Diagnostics do not themselves change acceptance. The separately documented [returned-scope policy change](LAB-COOKIE-SCOPES.md) intentionally replaces a permission-name allowlist with RFC 6749 syntax validation; its predicate is now `ScopeSyntax`. All other rejection checks, comparisons, optional fields, destinations, requested scopes, request order, deadlines, size bounds, cleanup order and success receipt remain in force. No sign-in, consent, additional request or live retry is authorized by these diagnostics.

A failure retains the fixed message `Server-backed session probe failed; no live acceptance. Sensitive details suppressed.` and appends exactly three bounded labels:

`Phase=<fixed phase>; Code=<fixed category>; Predicate=<fixed identifier>.`

All three must be actual scalar strings and an allowed combination. Unknown types, labels, casing or combinations become `Phase=Unknown; Code=UnexpectedFailure; Predicate=UnexpectedFailure`. Labels are assigned only from local literals. The public error does not contain exception messages/types, response bodies or headers, URLs, tokens, cookies, claim values, granted scope strings or identifiers.

## Interpretation

- A rejection identifier is assigned only after its existing rejection condition evaluates true. Checks retain their original order and short-circuit behavior; the first rejecting check wins.
- An operation identifier is assigned immediately before entering that operation. It identifies where execution failed, not its underlying cause. For example, `TransportSend` does not establish a DNS, TLS, server or authentication problem, nor prove that any request reached a service.
- While a guard is being evaluated, an unexpected evaluation failure uses the phase's generic `UnexpectedFailure` category and identifier rather than claiming the guard rejected its input. Successful helpers clear their operation state.
- If a primary failure is followed by a disposal failure, the primary identifier is retained. Cleanup still stops/throws at the same place as before; the diagnostic is not a description of the terminal exception. Disposal-only failures identify the entered disposal operation.
- `TransportFailure` is the new bounded category for transport rejection/operation identifiers. `ClockRead` belongs to `UnexpectedFailure`, not to a failed token-time validation.
- Optional returned `scope`, `azp` and `nbf` remain optional. The refresh-token check preserves the original value-truthiness test; it has not become a property-absence rule. Header/claim parsing still precedes algorithm, binding, time and UserInfo checks in the original order.

Older errors with only a generic or broader category cannot be retroactively resolved into one of these predicates. A diagnostic alone does not justify relaxing a check or changing a request.

## Complete fixed vocabulary

Every phase below additionally permits `Code=UnexpectedFailure; Predicate=UnexpectedFailure`. No cross-phase or cross-category combinations are inferred from a predicate name.

### Configuration / InvalidConfiguration

- `TenantFormat`, `TenantNonzero`, `ClientFormat`, `ClientNonzero`.
- `UpnLength`, `UpnFormat`.

### Configuration / UnexpectedFailure

- `ConfigurationValidation`.

### Cookie / InvalidCookie

- `CookieName`, `CookieLength`, `CookieAlphabet`.

### DiscoveryMetadata / InvalidMetadata

- `IssuerMetadataString`, `IssuerMetadataMatch`, `AuthorizationMetadataString`, `AuthorizationMetadataMatch`.
- `TokenMetadataString`, `TokenMetadataMatch`, `UserInfoMetadataString`, `UserInfoMetadataMatch`.

### AuthorizationResponse / InvalidAuthorizationResponse

- `AuthorizationStatus`, `AuthorizationLocationCount`.

### Callback / InvalidCallback

- `CallbackUriConstruction`, `CallbackScheme`, `CallbackHost`, `CallbackPort`.
- `CallbackUserInfo`, `CallbackFragment`, `CallbackPath`, `CallbackQueryParsing`.
- `CallbackKeyName`, `CallbackKeyMultiplicity`, `CallbackErrorAbsent`, `CallbackStateMatch`.
- `CallbackCodePresent`, `CallbackCodeLength`.

### TokenResponse / InvalidTokenResponse

- `TokenTypeString`, `TokenTypeBearer`, `AccessTokenString`, `AccessTokenNonblank`.
- `AccessTokenNoNewline`, `IdTokenString`, `RefreshTokenFalsey`, `ScopeString`.
- `ScopeSyntax`.

### TokenEncoding / InvalidTokenEncoding

- `TokenSplit`, `TokenPartCount`, `HeaderAlphabet`, `HeaderLength`.
- `HeaderBase64Decode`, `HeaderUtf8Decode`, `HeaderJsonParse`, `HeaderJsonRootObject`.
- `HeaderJsonPropertySetConstruction`, `HeaderJsonPropertiesRead`, `HeaderJsonPropertyUnique`, `HeaderJsonConversion`.
- `HeaderJsonDispose`, `ClaimsAlphabet`, `ClaimsLength`, `ClaimsBase64Decode`.
- `ClaimsUtf8Decode`, `ClaimsJsonParse`, `ClaimsJsonRootObject`, `ClaimsJsonPropertySetConstruction`.
- `ClaimsJsonPropertiesRead`, `ClaimsJsonPropertyUnique`, `ClaimsJsonConversion`, `ClaimsJsonDispose`.
- `HeaderAlgorithmString`, `HeaderAlgorithmMatch`, `HeaderCriticalAbsent`, `SignatureAlphabet`.
- `HeaderUtf8Construction`, `ClaimsUtf8Construction`.

### TokenBinding / InvalidTokenBinding

- `IssuerClaimString`, `IssuerClaimMatch`, `AudienceClaimString`, `AudienceClaimMatch`.
- `TenantClaimString`, `TenantClaimMatch`, `NonceClaimString`, `NonceClaimMatch`.
- `AuthorizedPartyString`, `AuthorizedPartyMatch`, `ObjectIdString`, `ObjectIdFormat`.
- `ObjectIdNonzero`, `UsernameString`, `UsernameMatch`, `SubjectString`.
- `SubjectNonblank`.

### TokenTimes / InvalidTokenTimes

- `IssuedAtInteger`, `ExpiryInteger`, `ExpiryFuture`, `IssuedAtNotFuture`.
- `IssuedAtRecent`, `ExpiryAfterIssuedAt`, `NotBeforeInteger`, `NotBeforeNotFuture`.

### UserInfoSubject / InvalidUserInfoSubject

- `UserInfoSubjectString`, `UserInfoSubjectMatch`.

### DiscoveryRequest / UnexpectedFailure

- `RequestInvocation`.

### AuthorizationRequest / UnexpectedFailure

- `StateCreation`, `NonceCreation`, `VerifierCreation`, `ChallengeCreation`.
- `AuthorizationFormCreation`, `AuthorizationUriConstruction`, `RequestInvocation`.

### TokenRequest / UnexpectedFailure

- `TokenFormCreation`, `RequestInvocation`.

### UserInfoRequest / UnexpectedFailure

- `RequestInvocation`.

### TokenTimes / UnexpectedFailure

- `ClockRead`.

### Shared JSON-response validation

These `InvalidResponse` identifiers are allowed independently in `DiscoveryResponse`, `TokenResponse` and `UserInfoResponse`, in this order:

- `ResponseStatus`.
- `ResponseMediaType`.
- `ResponseLocations`.
- `ResponseJsonParse`.
- `ResponseJsonRootObject`.
- `ResponseJsonPropertySetConstruction`.
- `ResponseJsonPropertiesRead`.
- `ResponseJsonPropertyUnique`.
- `ResponseJsonConversion`.
- `ResponseJsonDispose`.

### Shared transport operations

These `TransportFailure` identifiers are allowed independently in `DiscoveryRequest`, `AuthorizationRequest`, `TokenRequest` and `UserInfoRequest`. They cover the same transport helper at each call site; no new request path is introduced.

- `TransportUriConstruction`, `TransportScheme`, `TransportPort`, `TransportUserInfo`.
- `TransportFragment`, `TransportHost`, `TransportHandlerConstruction`, `TransportRedirectPolicy`.
- `TransportCookiePolicy`, `TransportCredentialPolicy`, `TransportProxyPolicy`, `TransportClientConstruction`.
- `TransportTimeoutConfiguration`, `TransportMethodConstruction`, `TransportRequestConstruction`, `TransportBufferConstruction`.
- `TransportHeaderConstruction`, `TransportBodyConstruction`, `TransportSend`, `TransportAdvertisedLimit`.
- `TransportDeadlineConstruction`, `TransportStreamOpen`, `TransportReadBufferConstruction`, `TransportRead`.
- `TransportStreamedLimit`, `TransportBufferWrite`, `TransportLocationRead`, `TransportResponseProjection`.
- `TransportUtf8Decode`, `TransportStreamDispose`, `TransportResponseDispose`, `TransportDeadlineDispose`.
- `TransportBufferDispose`, `TransportRequestDispose`, `TransportClientDispose`.

## Coverage and limitations

[`LabSessionProbe.Tests.ps1`](../tests/LabSessionProbe.Tests.ps1) keeps all previous negative fixtures, checks the exact first predicate, asserts no downstream request or partial public receipt, and inspects every output stream and rendered exception/error for synthetic secret markers. It adds multiple-failure order cases, compatibility cases for optional/falsey values, every allowed emission tuple, and poisoned labels/tuples. Ordinary unchanged synthetic protocol fixtures also compare acceptance, receipt and the complete normalized request trace against the immutable current-base probe. Explicit scope-expansion fixtures instead assert the intentional old rejection/new acceptance, a byte-identical shared request prefix with deterministic transaction values, and only the newly reached UserInfo request. This is semantic request equivalence, not a raw-byte claim: query/form fields are decoded and sorted, and transaction-random state, nonce, challenge and verifier values are replaced with fixed placeholders. Separate source checks pin the unchanged form encoder, form/query expressions and request arguments.

The protocol baseline is the exact published probe from canonical commit `9dbbf1c4aa8990a2d3b4d9f926e7b36a68ddfd30`, SHA-256 `71591b0bb059220a64043b3232e445e7d0247cf1cb3bf19f0127791b3060a123`, stored as [`LabSessionProbe.ScopeBaseline.ps1`](../tests/fixtures/LabSessionProbe.ScopeBaseline.ps1). The existing native transport suite retains its prior immutable [`LabSessionProbe.Baseline.ps1`](../tests/fixtures/LabSessionProbe.Baseline.ps1), canonical commit `6c6c04aa68ac1c94dae2377b3aea82934419b438`, SHA-256 `9a42b6785d3d4e70108b0d8d4cb88c106123adb4994b564a0b2ab3f7a6d639cc`. Both are hash-checked and loaded only through isolated AST harnesses. Native factories are excluded; protocol tests replace both transport boundaries completely.

[`LabSessionTransport.Tests.ps1`](../tests/LabSessionTransport.Tests.ps1) exercises the actual transport helper with an in-process fake handler and streams, including destination rejection, send/open/read failures and cancellation, advertised/streamed limits, malformed UTF-8, disposal-only failures, and primary failures followed by disposal failures. It also compares baseline/candidate native-helper results, request traces and cleanup behavior. The native handler factory is never loaded.

Coverage is deliberately distinguished:

| Boundary | Executable offline coverage | Static-only coverage |
| --- | --- | --- |
| Configuration, cookie, metadata, callback, token fields, binding, times, subject | Existing rejection predicates, exact boundary values, multiple failures/order and compatibility | Uninjectable primitive/runtime failures are not fabricated |
| JSON | Malformed JSON, root shape, case-insensitive duplicates, depth/conversion failure | Hash-set creation, property enumeration and JsonDocument disposal failure placement |
| Transaction and token encoding | Mocked entropy/form/configuration failures, malformed parts/UTF-8/JSON, all existing guards | Uninjectable URI/query/clock/codec operations and base64 decode after valid alphabet/length; source placement/order only |
| Native transport | Fake handler/stream faults, request/response content disposal, first-failure retention and differential behavior | Real handler construction/policy-setting, nonvirtual framework operations and deadline/buffer disposal placement |
| Public emission | Every fixed tuple and invalid scalar/type/combination fallback, all-stream and rendered-error secrecy | Static finite-vocabulary and guard-assignment contracts |

Static source checks do not prove that a native constructor or disposal fault occurred. Synthetic exceptions and fake-handler behavior do not prove real networking, TLS, service acceptance, credential validity or elapsed connect timing. The existing slow offline test checks only the production body-read deadline against a non-network blocked stream. No test opens a real network path.
