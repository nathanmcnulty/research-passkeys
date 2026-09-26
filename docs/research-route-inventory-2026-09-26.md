# Research Function route and contract inventory

Reviewed 2026-09-26 against research commit `662b3276f1084644111f4e79c48f7393bc3df2b5`. This is a source and local-test inventory. No deployed Function, Azure configuration, caller identity, or RP result was inspected.

| Boundary | Source in both samples | Local evidence | Deployed evidence and remaining decision |
| --- | --- | --- | --- |
| Easy Auth issuer, audience, and calling application | Both `function-app/{python,powershell}/keyvault-passkey-http/infra/main.bicep` files declare `authsettingsV2`, global `requireAuthentication: true`, `Return401`, HTTPS, the selected tenant v2 issuer, `api://` audience, and allowed browser application. No `excludedPaths` is declared. | Python source-contract tests pass. This checks file shape, not platform enforcement. | Unverified. Select a deployment and test anonymous, wrong tenant/issuer, wrong audience, and wrong calling application through direct ingress. |
| Browser catalog and direct record ownership | Python `function_app.py` and PowerShell catalog handlers derive tenant/object identity from Easy Auth principal headers. List filters to owner; direct record/context/delete paths call owner checks; ownerless legacy records are denied. Browser catalog and assertion HTTP triggers are `anonymous` at the Functions layer and therefore rely on global Easy Auth plus application checks. | Source-contract tests pass; no live second-caller attempt. | Unverified. Exercise owner and second-caller list, direct record, context, status, and deletion routes against a selected lab deployment. Define delegation before allowing shared records. |
| Queue HTTP ingress | Entra ESTSAUTH and Okta IDX Queue triggers require a Function key in both samples. Python also extracts an authenticated caller to bind the queued owner; PowerShell does the same. The global Bicep Easy Auth setting has no Queue exclusion. | Tests confirm Function-key trigger levels and the global Bicep setting. No HTTP request was sent. | Whether an actual deployment requires both Entra identity and a Function key is unverified. Choose that contract explicitly before changing exclusions; test key-only, identity-only, and both on the selected deployment. |
| Function assertion | Python `assert_with_stored_passkey_http` and PowerShell `AssertWithStoredPasskey` return HTTP 501 before signing. The research browser `DevelopmentFunctionCatalogClient.assert` throws `NotSupportedError` before `fetch`. | Python source-contract tests pass. The denial was inspected in all three source paths; no live signing was attempted. | Preserve denial until fresh trusted presence/UV proof and the broker lifecycle contract exist. An RP result from another research flow does not close this gate. |
| Response cache controls | Python browser-context/delete and sensitive export/token paths use no-store helpers. Catalog list and direct-record GET now use the same no-store helper; the PowerShell routes pass `-NoStore` to their existing JSON response helper. The browser client also requests `cache: "no-store"`. | Source inspection and the local contract suites pass; the changed Function routes were not run in a hosted runtime. | Verify cache headers at direct ingress after deployment. Browser request mode alone is not a server policy. |
| Canonical Python library copy | `python/libraries/passkey/src/passkey` is the canonical library; the deployable Python Function carries `src/passkey`. The sync script replaces the deployable copy, so it was inspected but not run for this inventory. | Eight canonical files and eight deployable files have matching relative paths and SHA-256 hashes. | Recheck parity whenever library source changes and validate the deployed artifact separately. |

## Local baseline

| Check | Result |
| --- | --- |
| `python -m unittest discover -s function-app/tests -p 'test_*.py' -v` | 32 passed, 0 failed. These are primarily contract and source-shape checks. |
| `Invoke-Pester -Path ./powershell/tests/Passkey.Broker.Tests.ps1` | 7 passed, 0 failed. This mocks broker HTTP calls; it is not a deployed Function test. |
| SHA-256 comparison of canonical and deployable Python `passkey` trees | 8/8 files match, 0 path or hash differences. |
| `node browser-extensions/scripts/validate-upstream-provider-lock.mjs` | Validated all 50 immutable files of the historical provider baseline at `d7a6f357c35c`. The lock is a development snapshot, not an extension release. |

Local tool versions: Python 3.14.6, PowerShell 7.6.6, Pester 5.7.1, Node 26.7.0. The original `E:\research-passkeys` checkout contains pre-existing roadmap and TODO edits and remains untouched; this inventory was made in a clean worktree from `origin/main`.

## Route contract to resolve next

1. Select one existing lab Function deployment and record its exact artifact, profile, auth settings, and route table without changing them.
2. Compare the deployed `authsettingsV2` and direct HTTP results with the source matrix above. In particular, settle whether Queue ingress requires identity plus key or a narrowly scoped exception. Do not infer an exception from the historical browser TODO.
3. Verify owner and second-caller behavior on catalog and direct-record routes, expected assertion 501 with no signing, and response cache headers. Use sanitized request IDs and responses.
4. If source and deployment differ, prepare a scoped config/code diff and deployment what-if before changing the lab. Keep assertion signing disabled while the trusted proof and broker contract remain unresolved.
