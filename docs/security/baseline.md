# Security baseline

These constraints should shape shared code and templates in this repo:

1. Private keys should remain in Azure-managed signing backends when the design calls for Key Vault-backed passkeys.
2. Shared code should default toward claims-aware, policy-compliant auth flows.
3. Credential metadata should be encrypted at rest and versioned for migration.
4. Compatibility-only flows should be clearly labeled so they are not mistaken for the preferred production path.
5. Browser-extension, Function App, and Windows provider tracks should share contracts where possible without overstating parity where it does not yet exist.

This repo should favor explicit security posture over convenience-driven drift between tracks.
