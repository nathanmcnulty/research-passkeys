# Session reuse and scope observations

## Acceptance is not a permission-name policy

The probe still requests exactly `openid profile`, with the same reviewed client,
callback, PKCE, state and nonce. A returned permission list need not equal the
requested list. The probe does not establish consent, effective permissions, access
to another resource, or whether every permission appears in a token claim.

This revision intentionally removes the old returned-name restriction to `openid`
and `profile`. It is an acceptance-policy change, not a diagnostic-only repair.
Every other acceptance check is unchanged: token type, access-token shape, fresh
ID-token encoding and identity/binding/time checks, refresh-token truthiness rejection,
and matching UserInfo subject. Access tokens are sent only to the same allowlisted
UserInfo endpoint. There is no permission probing or additional request.

Optional token-response `scope` has these protocol rules:

- Omission remains accepted.
- If present, it must be an actual, nonempty string, not null, a number or an array.
- RFC 6749 scope-token characters are ASCII `0x21`, `0x23–0x5B` and `0x5D–0x7E`.
  Names have exactly one ASCII space between them; empty entries, controls, Unicode,
  double quotes and backslashes are rejected. No trimming or case folding occurs.
- Names, order, case and duplicates are not a permission policy. Valid names outside
  the old list now pass this check. Syntax failures use the fixed `ScopeSyntax`
  predicate, with no returned value in the error.

These syntax rules apply whether or not observations are enabled. The existing
64-KiB response transport bound remains; observation bounds below do not restrict
protocol acceptance. In particular, RFC-valid punctuation or long lists may pass
acceptance but be unavailable in the narrower local observation representation.

## Explicit, in-memory opt-in

`Invoke-LabSessionProbe` accepts an optional `ScopeObservation` parameter of type
`System.Collections.Generic.List[object]`. The caller supplies an empty concrete
list to opt in. Its contents are cleared at invocation start, including on failed
authentication, so an earlier snapshot is not mistaken for a new result. The list
receives exactly one snapshot only after all acceptance checks, including UserInfo,
succeed. No diagnostic extraction runs after a failed acceptance check.

The default is null: no access-token decoding, observation, extra success-stream
item or name output occurs. The ordinary success receipt remains the same four
Boolean fields. No current controller workflow opts in. There is no file writer,
logging, workflow output, network export, artifact or publication path for these
observations. A future export requires separate review of its destination and
audience. Scope names reveal permission metadata: the name grammar is only a shape
filter, not proof that its contents are nonsensitive. Public-repository Actions logs
and artifacts are not private export destinations. Approval for in-memory preparation
does not approve public output or a later export. The list is trusted caller-owned
in-process storage, not a security boundary against caller mutation or concurrent use.

The snapshot contains exactly two independently observed properties:

- `ResponseScope`: provenance `TokenResponseScope`.
- `AccessTokenScp`: provenance `UnverifiedAccessTokenScp`.

Each contains only `Provenance`, `Status`, `ObservedAtUtc` and `Names`. The timestamp
is one locally sampled UTC observation time in round-trip format, not token issue
time, grant time or a server claim. Status is `Available`, `Absent` or `Unavailable`.
Names is always a string array, empty unless available. No requested-scope list,
other claim, header value, identity, token, cookie, endpoint or server metadata is
included. The two lists may disagree and are never merged or treated as authority.

Unexpected local projection/timestamp faults leave the list empty and do not
change the successful receipt, request count or failure diagnostic state. A normal
unsupported/malformed input produces an `Unavailable` source observation instead.

## All-or-nothing observation bounds

For either source, a representable list must meet every rule:

- At most 4,096 source characters and 64 names, with one ASCII space between names.
- Each name is 1–128 characters: an ASCII letter first, then only ASCII letters,
  digits, period, underscore or hyphen.
- Case, order and duplicate entries are preserved exactly; duplicates count toward
  both limits. There is no filtering, truncation, sorting or deduplication.

If any name or bound fails, the entire source is `Unavailable` with an empty array,
not a partially approved list. These narrow rules are deliberately not OAuth scope
syntax or a complete model of Entra permission names. Omitted response `scope` is
`Absent`; a present valid protocol value outside these bounds is `Unavailable`.

The optional access-token reader treats tokens as unverified local input:

- At most 16,384 token characters, checked before splitting or decoding.
- Exactly three nonempty base64url segments; each length modulo four must not be one.
- Header and payload each decode to at most 8,192 bytes and strict UTF-8 JSON objects,
  with maximum JSON depth 16. Top-level duplicate property names, including case
  variants such as `scp`/`SCP`, make the observation unavailable.
- Only an exact-case top-level `scp` string is projected through the same name rules.
  A well-formed supported object without `scp` is `Absent`. A wrong-type, empty,
  malformed or unrepresentable `scp` is `Unavailable`.

Opaque tokens, unsupported JWT shapes, bad encoding/Unicode/JSON or exceeded bounds
are unavailable observations, not new authentication failures. Header parsing checks
representation only; there is no signature, algorithm, issuer, audience, lifetime or
permission validation of this access token. No other claim is interpreted. A decoded
`scp` cannot prove effective authority and may change over time. Decoded byte buffers
are cleared in finally blocks; raw string references are dropped best-effort, which
does not guarantee managed-string zeroization.

## Offline evidence

The synthetic protocol suite explicitly tests both unchanged behavior and the
intended old/new acceptance differences against the hash-pinned current published
probe. It covers RFC character ranges, omissions and malformed values, unchanged
request fields, rejection order and stopping before downstream requests. Scope
observation tests use isolated non-network fixtures, check exact output projections
and all output streams, exercise Unicode/control/duplicate/size boundaries and
verify that omitted opt-in, failed authentication and local observation faults
cannot leak names or change the receipt. Native transport is unchanged.

No offline test proves live session reuse, actual returned permission names,
service behavior, consent or resource access. This change includes no live retry.

## Primary references

- [RFC 6749 section 3.3: scope syntax](https://www.rfc-editor.org/rfc/rfc6749#section-3.3).
- [Microsoft: UserInfo access-token response scopes](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#get-an-access-token-for-the-userinfo-endpoint), including previously granted Graph permissions and tokens that may not be JWTs.
- [Microsoft: access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens): clients treat them as opaque; local decoding is for debugging, not client authentication validation.
