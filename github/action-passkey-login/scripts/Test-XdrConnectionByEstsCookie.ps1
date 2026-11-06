#!/usr/bin/env pwsh
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EstsCookieValue,

    [Parameter()]
    [string]$EstsCookieName = 'ESTSAUTH',

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($EstsCookieValue)) {
    throw 'EstsCookieValue cannot be empty.'
}

if ([string]::IsNullOrWhiteSpace($EstsCookieName)) {
    throw 'EstsCookieName cannot be empty.'
}

$EstsCookieName = $EstsCookieName.Trim()
$EstsCookieValue = $EstsCookieValue.Trim()
$TenantId = if ([string]::IsNullOrWhiteSpace($TenantId)) { $null } else { $TenantId.Trim() }

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = $UserAgent

# Bootstrap the Microsoft login cookie container before adding the ESTS cookie.
$null = Invoke-WebRequest `
    -UseBasicParsing `
    -MaximumRedirection 99 `
    -ErrorAction SilentlyContinue `
    -WebSession $session `
    -Method Get `
    -Uri 'https://login.microsoftonline.com/error' `
    -Verbose:$false

$cookie = [System.Net.Cookie]::new($EstsCookieName, $EstsCookieValue)
$session.Cookies.Add('https://login.microsoftonline.com/', $cookie)

$securityPortalUri = if ($TenantId) {
    "https://security.microsoft.com/?tid=$TenantId"
} else {
    'https://security.microsoft.com/'
}

$securityPortal = Invoke-WebRequest `
    -UseBasicParsing `
    -ErrorAction SilentlyContinue `
    -WebSession $session `
    -Method Get `
    -Uri $securityPortalUri `
    -Verbose:$false

if ($securityPortal.InputFields.name -notcontains 'code') {
    try {
        $securityPortal.Content -match '{(.*)}' | Out-Null
        $sessionInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        throw "Failed to complete XDR authentication flow using cookie '$EstsCookieName'."
    }

    if ($sessionInformation.sErrorCode -eq '50058') {
        throw "Session information is not sufficient for XDR single sign-on using cookie '$EstsCookieName'. Acquire a fresh ESTSAUTH cookie and try again."
    }

    if ($sessionInformation.sErrorCode) {
        throw "XDR authentication flow failed with error code $($sessionInformation.sErrorCode) using cookie '$EstsCookieName'."
    }

    throw "XDR authentication flow failed using cookie '$EstsCookieName'."
}

$requiredFields = @('code', 'id_token', 'state', 'session_state', 'correlation_id')
foreach ($field in $requiredFields) {
    if (-not ($securityPortal.InputFields.name -contains $field)) {
        throw "Required field '$field' is missing from the XDR response when using cookie '$EstsCookieName'."
    }
}

$body = @{}
foreach ($field in $requiredFields) {
    $body[$field] = $securityPortal.InputFields | Where-Object { $_.name -eq $field } | Select-Object -ExpandProperty value
}

try {
    $portalResponses = @(Invoke-WebRequest `
        -UseBasicParsing `
        -ErrorAction Stop `
        -WebSession $session `
        -Method Post `
        -Uri $securityPortalUri `
        -Body $body `
        -Verbose:$false)
    if ($portalResponses.Count -ne 1) { throw 'Ambiguous portal response.' }
    $portalResponse = $portalResponses[0]
    if (-not $portalResponse -or [int]$portalResponse.StatusCode -lt 200 -or [int]$portalResponse.StatusCode -ge 300) {
        throw 'Unsuccessful portal response.'
    }
} catch {
    # Do not expose exception details or server content containing authentication material.
    throw 'XDR portal bootstrap form exchange failed; authenticated access remains unverified.'
}

$xdrCookies = $session.Cookies.GetCookies('https://security.microsoft.com')
if (-not $xdrCookies -or $xdrCookies.Count -eq 0) {
    throw "XDR session cookies were not established using cookie '$EstsCookieName'."
}

[PSCustomObject]@{
    # Compatibility field deliberately stays false: portal cookies are not proof of authentication.
    Success = $false
    BootstrapCompleted = $true
    AuthenticationVerified = $false
    ValidationScope = 'PortalBootstrapOnly'
    EstsCookieName = $EstsCookieName
    SecurityPortalUri = $securityPortalUri
    XdrCookieNames = @($xdrCookies | Select-Object -ExpandProperty Name | Sort-Object -Unique)
}