# Passkey catalog and key metadata

## Decision

Use Azure Key Vault only for passkey signing keys and Azure Table Storage for the canonical passkey catalog.

The portable record is defined by `contracts/passkey-catalog-record.schema.json`. It deliberately contains enough information to select a credential and construct the existing login credential, but it contains no private key material, access token, browser cookie, registration state, or authorization policy.

The optional `loginContextSecretName`, `hasStoredPassword`, `hasStoredUserAgent`, and `latestCaptureId` fields are references and availability flags only. Durable password/user-agent values live together in a Key Vault secret; short-lived full capture payloads use the separate encrypted capture design documented in `passkey-capture-context.md`.

This split supports two access modes without changing the record:

1. **Broker mode (target production design):** a middle layer has Table and Key Vault data-plane access. It authenticates the caller, evaluates per-credential policy, resolves the catalog record, and signs with Key Vault. Callers have no direct data-plane access.
2. **Direct development mode:** a developer authenticates to Table Storage and Key Vault with Azure CLI or another development identity. The same catalog can be queried without running the broker.

Function keys protect the sample HTTP routes, but they are not user authorization. The catalog endpoints must not be treated as a production RBAC boundary until caller-token validation and per-record policy enforcement are added.

## Table mapping

The sample stores records in `PasskeyCredentials` by default.

| Table field | Value |
| --- | --- |
| `PartitionKey` | lower-case Key Vault name |
| `RowKey` | `recordId` |
| query columns | schema version, provider, credential ID, RP ID, user name, display name, key coordinates, status, timestamps, sign count |
| `RecordJson` | complete canonical catalog record |

The explicit columns make basic development queries possible while `RecordJson` prevents the Table transport from becoming the domain contract. A future SQL, Cosmos DB, or broker-owned store can persist the same record.

This is intentionally a catalog, not a discovery scan of Key Vault. Listing Key Vault keys cannot reliably reconstruct WebAuthn credential IDs, user handles, provider metadata, or lifecycle state. Key Vault key listing may be used by an administrative reconciliation job, but it is not the application index.

## Lookup behavior

The Function samples expose:

- `GET /api/entra/passkeys[/{recordId}]` for provider-scoped Entra lookup
- `GET /api/okta/passkeys[/{recordId}]` for provider-scoped Okta lookup
- `GET /api/passkeys` to list records in the configured vault
- `GET /api/passkeys/{recordId}` to load one record
- optional `provider`, `rpId`, `userName`, and `status` query filters on the list route
- provider-scoped and generic list routes also support `credentialId`, `displayName`, and `keyVaultKeyName`/`keyName` for exact key selection

Registration writes the catalog record before returning success. If catalog persistence fails, registration reports failure even though the newly created Key Vault key and remote passkey enrollment may require reconciliation. This avoids silently returning an untracked credential.

## Security and evolution

- Azure Storage encryption at rest and RBAC are the baseline for the sample.
- Treat user names, credential IDs, and user handles as sensitive metadata; do not log full records.
- Keep ACLs and approval/JIT state in separate policy records so mutable authorization does not change the passkey contract.
- Use optimistic concurrency when sign counters or lifecycle state become writable through the broker.
- A higher-assurance client-held metadata design may encrypt `RecordJson`, but fields needed for broker-side selection and policy evaluation must remain queryable or gain a separate protected index.
- Direct development roles should be time-bound and limited to the development storage account and vault. Production clients should call the broker only.
