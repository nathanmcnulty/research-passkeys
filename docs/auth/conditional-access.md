# Conditional Access and auth strategy

## Standard auth posture

The default auth path for new work in this repo should be a claims-aware delegated token abstraction, not raw ESTS cookie handling.

That shared auth layer should own:

- delegated token acquisition
- claims-challenge handling
- interactive fallback behavior
- parent-window or host UX hooks where needed
- device-registration assumptions
- KMSI policy

## Preferred auth tiers

### Tier 1: delegated user auth with claims-aware token providers

Use this when the scenario is user-driven and must behave well under Conditional Access:

- WAM/MSAL-style flows for Windows and .NET hosts
- browser-appropriate delegated flows for browser tracks
- future Python flows that can respond to claims challenges rather than assuming static credentials

This is the primary path for code that should become shared guidance.

### Tier 2: workload auth for automation or hosted execution

Use this when the code runs outside an interactive user session:

- managed identity
- certificate-based auth
- service principal auth when required

This is appropriate for Function App samples, background jobs, and controlled automation cases.

### Tier 3: compatibility and research-only cookie/session flows

Raw ESTSAUTH or `WebSession`-driven flows can remain in this repo, but they should be treated as:

- troubleshooting tools
- protocol research aids
- compatibility-only samples

They should not define the standard auth story for new shared code.

## KMSI guidance

- Do not let "Keep me signed in" handling leak into each host independently.
- Centralize any persistence/session policy in shared auth guidance and helpers.
- Document whether a flow expects transient interactive auth, persistent browser session state, or workload credentials.

## Requirements for shared auth code

Shared auth code should make these behaviors explicit:

1. what scopes/resources it requests
2. whether interactive fallback is allowed
3. how claims challenges are surfaced and retried
4. whether the host can supply a parent window or UI callback
5. whether token persistence or session persistence is expected

If those behaviors differ by host, the host should supply configuration and UX hooks, not reimplement the auth flow from scratch.
