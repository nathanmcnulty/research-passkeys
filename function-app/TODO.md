# Function App security TODO

2026-09-26 source review: both Function Bicep samples already declare global Easy Auth with issuer, audience, and allowed calling application. The checked source settings have not been verified on a deployed Function. See [the route inventory](../docs/research-route-inventory-2026-09-26.md) before changing authentication policy.

The following hardening work remains for both the PowerShell and Python Function samples. Items already implemented in infrastructure or application code are intentionally excluded.

## Caller authentication and authorization

- [x] Declare App Service Authentication (`authsettingsV2`) in both Bicep samples. Verify the effective deployed setting separately.
- [x] Declare the expected tenant issuer, application audience, allowed calling application, and unauthenticated HTTP 401 response in both Bicep samples. Verify the effective deployed behavior separately.
- [ ] Define the broker authorization contract mapping an authenticated caller to permitted catalog records and Key Vault operations.
- [ ] Decide whether Function keys remain as defense-in-depth once Entra authentication is enforced.

## Secret handling

- [ ] Require TAPs, ESTSAUTH cookies, Okta cookies/state handles, passwords, and access tokens in request bodies or the `Authorization` header; reject these fields in query strings.
- [ ] Add explicit poison-queue cleanup and redaction so failed registration messages do not retain reusable session material.
- [ ] Review Application Insights telemetry to ensure authentication artifacts are never recorded.

## Error handling

- [ ] Replace raw exception text in HTTP responses with stable error codes and correlation IDs.
- [ ] Log redacted diagnostic details server-side and test that provider response bodies and secrets cannot reach clients.

## Function host hardening

- [ ] Enable `functionsRuntimeAdminIsolationEnabled` after validating operational tooling.
- [ ] Disable FTP, remote debugging, and basic publishing credentials where compatible with code deployment.
- [ ] Add explicit request-size limits and review CORS before adding any browser client.

## Edge protection

- [ ] Put internet-facing production endpoints behind API Management or an equivalent broker/edge service.
- [ ] Add per-caller rate limits, payload limits, abuse monitoring, and, if warranted, WAF policy.

## Supply chain

- [ ] Lock Python dependencies to tested versions with hashes or an equivalent reproducible build mechanism.
- [ ] Narrow the Functions extension bundle version range after compatibility testing.
- [ ] Add dependency, secret, and infrastructure scanning to CI.

## Production follow-ups

- [ ] Evaluate private endpoints and private DNS for Storage, Key Vault, and Function ingress. The current production profile uses VNet integration plus Storage and Key Vault service endpoints as its first isolation layer.
- [ ] Add alerts for denied Key Vault operations, key deletion attempts, unusual signing volume, Storage authorization failures, and poison-queue activity.
- [ ] Evaluate Premium Key Vault and HSM-backed EC keys for production assurance requirements.
