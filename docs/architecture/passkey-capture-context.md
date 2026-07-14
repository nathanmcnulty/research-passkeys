# Passkey capture and login context

## Storage boundaries

- `pklogin-{recordId}` is a versioned Key Vault secret containing `schemaVersion`, `password`, `userAgent`, and `updatedAt`. Missing input fields preserve the previous value. It has no automatic expiry and is removed only with explicit passkey/login-context lifecycle handling.
- The complete submitted capture JSON is serialized without dropping unknown fields and encrypted with a random 256-bit content-encryption key using AES-256-GCM.
- The encrypted envelope is stored in the private `passkey-capture-context` blob container. Its CEK is stored as `pkcek-{captureId}` with a 24-hour Key Vault expiry.
- `PasskeyCaptureContexts` contains searchable provenance and opaque references only. It never contains passwords, cookies, raw token collections, remote IP, or the complete user agent.

The AES-GCM additional authenticated data is `passkey-capture:v1:{provider}:{captureId}`. Applications enforce the 24-hour expiry before decryption. Storage lifecycle management deletes capture blobs after one day, while the cleanup timer removes provenance after 90 days.

## APIs

- `GET /api/passkeys/{recordId}/contexts` lists capture metadata.
- `GET /api/passkeys/{recordId}/contexts/{captureId}` returns one metadata record.
- `POST /api/entra/passkeys/{recordId}/login` and `POST /api/okta/passkeys/{recordId}/login` resolve the catalog and login context internally.
- `GET /api/passkeys/{recordId}/login-context/export` and `GET /api/passkeys/{recordId}/contexts/{captureId}/export` return secret material only when the deployment profile is `development` and `PASSKEY_ENABLE_DEV_SECRET_EXPORT=true`. Responses use `Cache-Control: no-store` and `Pragma: no-cache`.
- `DELETE /api/passkeys/{recordId}/login-context` soft-deletes the durable Key Vault secret and clears its catalog availability flags.

Queued registration encrypts the submitted payload before enqueueing. Queue messages contain only the encrypted capture reference and non-secret registration identifiers; workers decrypt the capture, register the passkey, and persist the final catalog/capture association.
