#Requires -Version 7.6

<#
.SYNOPSIS
Retrieves a reference ESTS cookie using a supplied secure Temporary Access Pass.
.DESCRIPTION
Requires a SecureString TAP, UPN and tenant GUID. The result contains a SecureString
CookieValue by default; -AsPlainText explicitly returns a raw bearer-cookie string.
No passkey is enrolled and no session is stored in global variables.
.EXAMPLE
$tap = Read-Host 'Temporary Access Pass' -AsSecureString
./Get-EntraEstsCookieViaTap.ps1 -TAP $tap -UserPrincipalName 'user@example.com'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Security.SecureString]$TAP,
    [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
    [string]$TenantId,
    [ValidateSet('SecurityInfoBootstrap')][string]$Purpose = 'SecurityInfoBootstrap',
    [switch]$AsPlainText
)

# Invoke public command
Get-EntraEstsCookieViaTap @PSBoundParameters
