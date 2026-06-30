# python

This folder contains canonical Python libraries and samples that align to the contracts in `contracts/`.

Current Python assets:

- `libraries\passkey`: canonical Python passkey registration and login helpers
- `function-app\python\keyvault-passkey-http`
- `samples\passkey-login`
- `samples\device-code-bootstrap`

Python should follow the same rules as the other tracks:

- use shared contract definitions
- keep host-specific glue local to the track
- promote cross-track logic only when it is genuinely reusable
