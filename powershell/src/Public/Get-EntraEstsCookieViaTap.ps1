function Get-EntraEstsCookieViaTap {
    <#
    .SYNOPSIS
    Retrieves an ESTS cookie using an explicitly supplied secure Temporary Access Pass.
    .DESCRIPTION
    Uses the shared My Sign-ins authentication flow, with bounded redirects, OAuth state
    checks, and client/tenant/user binding. No authentication runs when the module loads.
    The default result contains CookieName and a SecureString CookieValue. -AsPlainText
    returns only the raw cookie string for compatibility and exposes a bearer credential.
    No cookie or session is persisted to global scope. Protect returned cookies like passwords.
    This reference command does not enroll a passkey or establish authenticator assurance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.SecureString]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId,
        [ValidateSet('SecurityInfoBootstrap')][string]$Purpose = 'SecurityInfoBootstrap',
        [switch]$AsPlainText
    )
    Invoke-EntraEstsCookieViaTapUtility @PSBoundParameters
}
