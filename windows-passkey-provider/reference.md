# Windows passkey provider reference sources

Relevant Windows provider material currently lives in:

- `key-vault-passkey-provider\src\dotnet-provider`
- `key-vault-passkey-provider\src\cpp-provider`
- `key-vault-passkey-provider\src\winui-provider`
- `key-vault-passkey-provider\packaging`
- `key-vault-passkey-provider\docs\architecture.md`
- `key-vault-passkey-provider\docs\security-baseline.md`

The most reusable parts to pull toward `contracts\` and `shared\` are:

- stored credential and envelope contracts
- metadata protection patterns
- auth-provider abstractions
- Key Vault signing and wrapping helpers

The provider-specific parts that should stay in this track are:

- COM hosting and registration
- package identity experiments
- Windows-only WebAuthn provider plumbing
- sparse/full packaging details
