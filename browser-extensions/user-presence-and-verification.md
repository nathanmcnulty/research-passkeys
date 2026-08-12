# Browser User Presence and Verification Decision

Status: accepted research guidance, 2026-08-11

## Decision

Browser page activation, extension unlock, Entra sign-in, and a browser-local PIN must not be treated as automatic WebAuthn user presence or user verification.

- UP requires a fresh, trusted extension- or native-owned approval for the specific create/get ceremony.
- UV remains unsupported until a native companion performs Windows Hello or equivalent local verification and binds proof to that exact ceremony.
- a broker must not trust client-supplied `userPresent` or `userVerified` booleans.
- the authenticator component that authorizes the operation owns construction of authenticator data and sets flags only from verified internal state.

## Reusable work

Historical commit `ea260da` contains a useful extension-owned dialog, short-lived random session IDs, RP/origin display, and a constrained broker assertion prototype. The page/content relay and dialog interaction informed the canonical provider implementation.

The historical implementation must not be copied unchanged because it:

- set UP unconditionally in authenticator data.
- prompted only for `userVerification=required`.
- described the browser PIN as real UV.
- allowed the broker prototype to consume a client-supplied `userVerified` Boolean.

## Canonical implementation

The maintained implementation lives in `C:\GitHub\key-vault-passkey-provider\src\browser-extension`. The research repository should hold decisions, contracts, and comparative experiments rather than a second source copy.

Current canonical behavior:

- a fresh extension-owned approval is required before UP is set.
- approval state is short-lived, one-time, and bound in the background worker to the ceremony, RP, origin, top origin, and selected account.
- `userVerification=required` fails closed.
- attestation is `none`; the implementation makes no synthetic hardware, AAGUID, attachment, or transport claim.

## Future native proof contract

A future companion proof should cover a canonical transcript containing at least:

- protocol version and operation identifier
- create/get operation type
- RP ID, origin, and top origin
- credential ID or registration reservation ID
- hash of the exact client data and challenge
- broker nonce, issue time, expiry, and single-use identifier

The proof must be produced only after local verification, signed by an enrolled device-bound key, checked for freshness and replay at the broker, and consumed atomically with authorization and signing.
