# Broker coordination core

This is the canonical Python broker package selected by
[the proof/lifecycle contract](../contracts/broker-proof-lifecycle-v1.md).
It implements durable coordination and an authenticated preliminary WSGI API.
It is not connected to the research Functions, the provider extension or a
deployed endpoint. No production listener or deployment is included.

Implemented:

- Immutable owner partitions derived from the tenant/object identity supplied by
  a trusted server authentication boundary. Application allowlist and expiry
  are checked again before transaction dispatch and idempotent result replay.
- Atomic reservation and request-bound idempotency records. Conflicting reuse
  cannot overwrite a result; a lost acknowledgement can be retried with the same
  key without allocating a second credential.
- Per-credential preparation leases and uint32 counter allocation. Concurrent
  workers race on durable ETags. Expired preparations consume their counter;
  an unknown signing outcome never becomes permission to sign again.
- Owner revocation epochs and retained aborted registrations.
- Atomic deletion tombstones and pinned cleanup targets. Expired worker claims
  can be reassigned only before dispatch. A stale worker cannot acquire a dispatch
  ticket; a committed ticket cannot be replayed, even with the identical request
  key. Unknown dispatched work remains retained for reconciliation.
- Redacted mutation audit rows committed in the same transaction, with guard
  revision ordering. Idempotent replay does not duplicate the audit row.
- Entra v2 delegated JWT verification and a required authentication-context claim,
  with server-bound step-up challenges before storage access. The preliminary API
  exposes reservation/read/abort/preparation only; protected actions remain gated.

Activation and signing always raise `GateClosed`. Active records in tests are
seeded directly by storage fixtures; there is no activation flag, proof boolean,
test route, Key Vault signing client or production bypass. The API constructs
`AuthenticatedCaller` only after verified token admission. Live tenant-policy,
device/ceremony proof and RP acceptance evidence remain required. Delegation is
not enabled.

Lifecycle methods are internal state transitions. The API must verify operation-
specific proof before invoking protected transitions, including deletion; those
routes currently return 501. Cleanup claim/ticket methods have no public route
and must not become generic deletion endpoints. Cleanup completion remains
gated until an exact-key reconciliation adapter exists. This core never performs
a Key Vault DELETE.

## Preliminary API and authentication

`BrokerApplication` is a WSGI component, not a deployed service. It accepts only
Bearer access tokens for a configured public-cloud Entra tenant and dedicated v2
API audience GUID. `EntraConfig` requires approved client IDs, an explicit
delegated scope (default `Passkey.Access`) and a configured authentication-context
ID (`c1`–`c99`). There is no context-policy bypass/default. The host supplies
these values; request bodies and forwarded principal headers cannot set them.

The verifier pins RS256 and tenant-specific HTTPS signing keys, verifies
issuer/audience/time/version/tenant/object/client/scope, and requires the configured
`acrs` value. It rejects application-only and sender-constrained tokens, duplicate
JSON, weak/ambiguous keys, token-selected key URLs and non-UTF-8 encodings. Public
keys cache for five minutes; unknown-key refresh is limited to one attempt per
30 seconds and shared across threads. Metadata requests reject redirects and
compression, cap the body at 128 KiB, use connection/read timeouts, and send no
Bearer token, ambient `.netrc` credentials or proxy credentials.

An otherwise valid token without the required context gets a no-store 401 with
an `insufficient_claims` challenge bound to server configuration. MFA/UP/UV
booleans and `xms_cc` capability do not substitute for `acrs`. An identical
idempotent retry still passes current token/context checks before any cached
result is returned. This validates the signed claim, not whether a tenant's
configured CA policy is correct or enforced live; that remains a deployment gate.
See [Entra access-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference),
[claims challenges](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge),
and [confirmation-key semantics](https://www.rfc-editor.org/rfc/rfc7800).

| Method/path | Behavior |
| --- | --- |
| `POST /v1/reservations` | `{rpId}` and a 32-character hex `Idempotency-Key`; reserves an opaque credential handle |
| `GET /v1/credentials/{id}` | Owner-bound public projection; no key coordinates or claim secrets |
| `POST /v1/reservations/{id}/abort` | Empty JSON object and request key; aborts a non-active reservation |
| `POST /v1/credentials/{id}/prepare` | `{rpId,clientDataHash}` and request key; reserves a counter/nonce for an already active credential |
| Delete, finalize and sign paths | 501 until trusted operation-proof/RP integration exists |
| Cleanup claim/ticket paths | Not exposed |

All responses/errors are no-store. JSON bodies are UTF-8, reject duplicate or
unknown fields and are bounded to 8 KiB. Errors do not echo tokens, claims, raw
exceptions or private key coordinates. No credential can become active through
this API. A preparation is not a signature or current ceremony authorization.
The host still needs HTTPS, request deadlines, quotas/rate limits, reviewed CA
policy, production audit handling and authorized live validation before exposure.

## Transaction design

Each owner has a durable `owner` guard containing a monotonically increasing
revision and authorization epoch. Read it **before** reading dependent rows.
Every mutation atomically compares and advances that guard, with conditional
creates/updates for the changed credential, operation and request rows. Thus a
competing mutation invalidates the entire decision, including rows read without
being updated. A newly initialized owner or changed guard seen between GETs
causes a complete snapshot retry, including before classifying an apparent
state conflict/corruption. Only a definitively rejected 409/412 is retried. Other failures
retain an unknown outcome; SDK mutation retries are disabled in the client factory.
Connections have a five-second deadline and response reads a fifteen-second
deadline. Raw loopback HTTP fixtures verify that a 500, a dropped acknowledgement
and an elapsed response deadline each produce one POST, without an SDK resend.
The storage boundary also enforces monotonic guard revisions/epochs, independently
of lifecycle code.

All rows stay in one Azure Table partition. Transactions are capped at 16 rows,
with each canonical JSON payload capped at 16,000 ASCII characters. The service
must be the sole writer; direct client Table/Key Vault access is incompatible with
this authority boundary. No negative rows, idempotency records or guards are
automatically pruned. Retention/quota/backup rollback and multi-region failover
policy are deployment gates. The current memory adapter is strictly a test fixture.

An idempotency key is scoped to an owner partition and bound to action, target,
canonical payload and allowed application. Different owners have independent
namespaces; neither can retrieve the other's result. An identical retry can
return an earlier reservation/preparation result after it expires or is revoked;
that result is historical data, never current signing authority. Every later
transition must check current lifecycle, epoch and expiry.

Dispatch tickets trade availability for safety: after commit, lease expiry cannot
issue another ticket. Lost acknowledgement or a crash before dispatch can leave
work unknown indefinitely. A future trusted adapter must reconcile it; it cannot
assume a lease fences an already running Key Vault request, or that a caller's
boolean proves deletion. Key names/generations must remain exclusive and must
not be reused while any dispatch could be in flight.

The Azure Table adapter uses the documented [entity group transaction](https://learn.microsoft.com/en-us/rest/api/storageservices/performing-entity-group-transactions)
and [Python SDK conditional transaction](https://learn.microsoft.com/en-us/python/api/azure-data-tables/azure.data.tables.tableclient?view=azure-python)
interfaces. This core does not retrofit atomicity onto the extension's existing
Key Vault secret manifests or prevent an old direct client from signing.

## Local validation

From the repository root, using Python 3.11 or newer and Node.js 24:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r broker/requirements.lock
.venv/Scripts/python -m pip install --no-deps -e ./broker
npm ci --prefix broker/tools --ignore-scripts
.venv/Scripts/python broker/tools/validate.py
```

On Unix use `.venv/bin/python`. The harness starts a pinned, telemetry-disabled
Azurite Table process bound only to loopback, with disposable disk storage and
a public fixture account. It runs the same cases against the memory model and
real emulator ETag/batch requests. No ambient Azure configuration, token, live
storage account or vault is used. HTTP is allowed only through the explicit
loopback emulator option; configured storage endpoints otherwise require HTTPS.

The suite also starts independent Python broker processes to race reservations,
counter allocation and cleanup claims. A two-phase probe restarts both the broker
process and disk-backed emulator, preserving a counter, tombstone, idempotent
result and unknown dispatch. The emulator stops through its flush handler;
this proves normal process restart, not abrupt machine/power-loss durability.

`python -m unittest discover -s broker/tests -v` runs unit cases and explicitly
skips emulator cases when the harness is absent. Such skips are not an integration
pass. Emulator results establish local transaction behavior, not live Azure,
multi-region, native-proof or RP acceptance evidence.
