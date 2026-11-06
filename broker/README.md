# Broker coordination core

This is the canonical Python broker package selected by
[the proof/lifecycle contract](../contracts/broker-proof-lifecycle-v1.md).
It implements the first non-signing persistence slice. It is not connected to
the research Functions, the provider extension, or a deployed endpoint.

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

Activation and signing always raise `GateClosed`. Active records in tests are
seeded directly by storage fixtures; there is no activation flag, proof boolean,
test route, Key Vault signing client or production bypass. No HTTP API currently
constructs `AuthenticatedCaller`: eventual Entra verification, CA/device/proof
checks and RP acceptance integration remain required. Delegation is not enabled.

## Transaction design

Each owner has a durable `owner` guard containing a monotonically increasing
revision and authorization epoch. Read it **before** reading dependent rows.
Every mutation atomically compares and advances that guard, with conditional
creates/updates for the changed credential, operation and request rows. Thus a
competing mutation invalidates the entire decision, including rows read without
being updated. Only a definitively rejected 409/412 is retried. Other failures
retain an unknown outcome; SDK mutation retries are disabled in the client factory.

All rows stay in one Azure Table partition. Transactions are capped at 16 rows,
with each canonical JSON payload capped at 16,000 ASCII characters. The service
must be the sole writer; direct client Table/Key Vault access is incompatible with
this authority boundary. No negative rows, idempotency records or guards are
automatically pruned. Retention/quota/backup rollback and multi-region failover
policy are deployment gates. The current memory adapter is strictly a test fixture.

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

`python -m unittest discover -s broker/tests -v` runs unit cases and explicitly
skips emulator cases when the harness is absent. Such skips are not an integration
pass. Emulator results establish local transaction behavior, not live Azure,
multi-region, native-proof or RP acceptance evidence.
