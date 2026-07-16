# Browser extension broker TODO

The POC adapter in `keyvault-passkey-provider/` now uses Easy Auth plus a constrained Function assertion operation. It deliberately stops short of the complete production broker protocol below.

## Broker contract

- [ ] Define a versioned authenticator-facing API contract shared by the Python and PowerShell Function samples.
- [ ] Add a create/reserve operation that creates one P-256 Key Vault key and returns its public coordinates, key identifier, credential identifier, and an expiring reservation identifier.
- [ ] Add a finalize operation that persists the canonical catalog record only after the relying party accepts registration.
- [ ] Add an abort/cleanup operation for abandoned reservations and orphaned Key Vault keys.
- [ ] Add RP- and allow-list-aware credential discovery without returning records the authenticated caller cannot use.
- [x] Add a POC assertion operation that validates the record/RP relationship, constructs authenticator data, signs with Key Vault, and advances `signCount` (Python uses Table ETag; PowerShell CAS remains below).
- [ ] Add disable/delete lifecycle operations with reconciliation for the remote relying-party enrollment.
- [ ] Return stable error codes and correlation IDs instead of raw provider or Key Vault errors.

Do not expose a general `signDigest` route. The broker must constrain signing to an authorized active passkey record and its registered RP so the Key Vault key cannot become a generic signing oracle.

## Authentication and policy

- [x] Enable App Service Authentication with a dedicated single-tenant Entra application and validate issuer, audience, and calling application.
- [x] Replace Function keys for browser catalog/assertion calls; keep exact Queue* ingress routes on Function keys outside Easy Auth.
- [ ] Define record ownership and administrative delegation policy, including how callers are mapped to permitted `recordId` values.
- [ ] Require recent extension PIN/UV proof where policy needs user verification, without accepting an unverified client-supplied UV bit as authoritative.
- [ ] Add per-user, per-record, and per-origin rate limits plus audit events for create, sign, disable, and delete operations.
- [ ] Put production ingress behind API Management or an equivalent policy edge and review CORS/extension-origin behavior.

## Concurrency and recovery

- [ ] Use Azure Table ETags or another compare-and-swap mechanism for `signCount` and lifecycle updates.
- [ ] Define retry/idempotency keys for create, finalize, and assertion requests so Function retries do not create duplicate keys or counters.
- [ ] Define extension cache freshness, offline behavior, and explicit revocation/tombstone handling.
- [ ] Add reconciliation for catalog records, Key Vault keys, and incomplete reservations.

## Extension migration

- [x] Route Function-catalog assertions through a constrained broker client; registration uses native fallback for this POC.
- [x] Use broker catalog discovery for the setup-wizard path.
- [x] Remove the Key Vault delegated scope and direct Key Vault data-plane permissions from the setup-wizard path.
- [x] Remove development Function-key input/storage from the setup-wizard path.
- [ ] Preserve the existing page/content/background WebAuthn relay, PIN prompt, account chooser, and RP/origin validation.
- [ ] Decide which component constructs attestation and assertion authenticator data, then document the trust and UV semantics explicitly.

## Validation

- [ ] Add contract tests that run identically against the Python and PowerShell Function implementations.
- [ ] Extend the CTAP test matrix to broker-created credentials, broker assertions, counter conflicts, disabled records, authorization failures, and retry/idempotency cases.
- [ ] Run an end-to-end Entra and Okta proof with a deployed development broker before promoting the protocol.
- [ ] Complete threat modeling for signing-oracle abuse, record enumeration, malicious RP input, extension compromise, replay, and Function-key leakage.
