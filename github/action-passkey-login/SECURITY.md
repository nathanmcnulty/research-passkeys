# Security Policy

## Supported Versions

The current `v1` release line is the supported public version of this action.

## Reporting a Vulnerability

Please do not open a public issue for vulnerabilities that could expose authentication material, session cookies, or tenant-specific security details.

Preferred reporting path:

1. Use GitHub private vulnerability reporting for this repository if it is available.
2. If private vulnerability reporting is not available, contact the repository owner directly and share only the minimum details needed to reproduce the issue.

When reporting a vulnerability, include:

1. A short description of the issue.
2. The affected file or workflow.
3. Reproduction steps.
4. The expected impact.
5. Whether the issue could expose passkey metadata, private key material, ESTS cookies, or downstream session cookies.

Please do not include live private keys, passkey files, ESTS cookie values, XDR session cookies, or long-lived secrets in the report.

## Security Notes for Users

This action handles sensitive authentication material.

Recommended usage:

1. Prefer Azure Key Vault-backed signing.
2. Use GitHub OIDC with `azure/login` instead of long-lived Azure client secrets.
3. Store passkey metadata and workflow configuration in GitHub secrets or variables as documented in [README.md](README.md).
4. Treat the `auth-cookie` output as sensitive session material.
5. Do not print ESTS cookie values or upload them as artifacts.

Less preferred usage:

1. Supplying `private-key` directly should be limited to local testing or tightly controlled automation.
2. Do not commit passkey JSON files or private keys to source control.

The passkey values used together in a workflow must come from the same registration:

1. `credential-id`
2. `user-handle`
3. `user-principal-name`
4. `key-vault-name`
5. `key-vault-key-name`