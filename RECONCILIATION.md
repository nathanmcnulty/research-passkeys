# Repository reconciliation

Reviewed 2026-09-28 against research `main` at `2e38eb569d8d8a84ac915c4d783ffbc8cf02fe9c` and provider `main` at `2fba00ed462061f08e4edc2ebf9dc68de9625aef`. Recheck those revisions before applying a later decision.

## What was preserved and brought current

The older `E:\research-passkeys` checkout had three two-line documentation edits and an untracked 110-line `ROADMAP.md` written against `1e797518` on 2026-09-12. All four files are preserved in [`codex/preserve-20260912-roadmap`](https://github.com/nathanmcnulty/research-passkeys/tree/codex/preserve-20260912-roadmap) at `ea38f26`. This branch is a review copy, **not** a proposed merge into current `main`. The local `main` checkout was then fast-forwarded by 26 commits to `origin/main`; no original edit was discarded.

| Preserved work | Current disposition |
| --- | --- |
| `README.md` link to the old roadmap | Do not copy as-is: the old roadmap points to a sibling local provider checkout and predates the current research/provisioning work. This document is the current entry point. |
| `browser-extensions/TODO.md` warning about disabled assertions and Queue/Easy Auth drift | Superseded by the newer 2026-09-27 warning and [extension reconciliation](browser-extensions/reconciliation.md). Function assertions still return 501, and the research browser adapter denies before network. |
| `function-app/TODO.md` warning that Bicep authentication exists but deployed behavior needs proof | The current source inventory covers the source claim. The browser TODO reports later management-plane verification in two isolated labs, while direct HTTP authorization is still unverified. Consolidate the underlying lab evidence before changing the Function TODO's deployed-status wording. |
| `ROADMAP.md` staged local, deployed Function, Entra/Okta, and broker plans | Retained for review. Its still-useful questions belong in the current [route inventory](docs/research-route-inventory-2026-09-26.md), [broker lifecycle contract](contracts/broker-proof-lifecycle-v1.md), or a focused new work item, rather than restoring a second competing roadmap wholesale. |

## Component ownership and parity

The hardened native provider and browser extension live in `keyvault-passkey-provider/src/dotnet-provider` and `keyvault-passkey-provider/src/browser-extension` in the provider repository. Research owns shared contracts, isolated Function experiments, and a pinned, immutable browser-extension source copy. The current 50-file provider extension tree matches `browser-extensions/upstream-provider.lock.json` at tree `f1c83328babfe2a0bce379629561dbebe1f02c27`; the lock's file hashes validate. The older runnable `browser-extensions/keyvault-passkey-provider` spike is divergent and has the same extension identity. Do not load or copy it over the hardened extension. Promote a bounded experiment to the provider through a reviewed provider PR, then refresh the research lock.

## Decisions still open

1. **Old extension spike:** compare its four research-only files and divergent overlapping behavior against the hardened source, then promote a specific safe feature or retire the spike. The same-identity hazard prevents using it as a second installed beta.
2. **Function authorization:** join the reported management-plane lab results to exact deployment IDs/configuration and test direct HTTP denial, owner isolation, and Queue identity-plus-key behavior. The source inventory and management-plane settings do not prove HTTP enforcement.
3. **Device-code samples:** several historical samples and README entries still describe or invoke device-code authentication. They are outside the approved working path; use cached WAM/MSAL or normal browser authentication. Decide whether to archive, disable, or replace each sample in a focused change. Do not run them as part of offline validation.
4. **Public release:** the provider's [release-readiness plan](https://github.com/nathanmcnulty/keyvault-passkey-provider/blob/main/plans/public-release-readiness.md) owns visibility, signed artifact, clean-host, security, and user-experience gates. Research results do not by themselves close those gates.

Keep the preservation branch until its roadmap questions have a disposition. Do not merge it wholesale or delete the older extension solely to make the working tree look cleaner.
