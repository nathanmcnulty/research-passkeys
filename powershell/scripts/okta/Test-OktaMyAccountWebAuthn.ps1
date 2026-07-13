#Requires -Version 7.0

<#
.SYNOPSIS
    Obtains a user-scoped Okta token with PKCE and starts a MyAccount WebAuthn enrollment.

.DESCRIPTION
    This diagnostic script verifies the supported Okta MyAccount WebAuthn API before
    creating an Azure Key Vault key or registering a credential.  It uses the OAuth
    authorization-code flow with PKCE against the Okta org authorization server, then
    calls POST /idp/myaccount/webauthn/registration.

    The OIDC application must be configured as a public client with this exact redirect
    URI and be granted the okta.myAccount.webauthn.manage scope on its Okta API Scopes tab.
    No secret is used or accepted.  The script deliberately does not print access tokens,
    authorization codes, or the registration challenge.

    The endpoint only begins an enrollment ceremony. It does not create a Key Vault key
    or persist a passkey in Okta.

.PARAMETER OktaDomain
    Okta org host name, for example contoso.okta.com. Do not include a path.

.PARAMETER ClientId
    Client ID of the public OIDC application that has the required Okta API scope grant.
    Required unless -AccessToken is supplied.

.PARAMETER RedirectUri
    Loopback redirect URI registered on the OIDC application. The default must be added
    to the application's Sign-in redirect URIs exactly as written.

.PARAMETER AccessToken
    Optional user access token. This is useful when testing a newly obtained token from
    a browser or an OAuth client. The script never writes the token to output.

.PARAMETER TimeoutSeconds
    Time to wait for the interactive browser authorization redirect.

.PARAMETER PassThru
    Returns the raw registration-start response. This contains a short-lived challenge;
    do not log or persist it.

.EXAMPLE
    # First create a SPA/native OIDC app, grant okta.myAccount.webauthn.manage, and add
    # http://127.0.0.1:8765/callback/ as a sign-in redirect URI.
    .\Test-OktaMyAccountWebAuthn.ps1 -OktaDomain 'contoso.okta.com' -ClientId '<client-id>'

.EXAMPLE
    .\Test-OktaMyAccountWebAuthn.ps1 -OktaDomain 'contoso.okta.com' -AccessToken $token
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OktaDomain,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [string]$RedirectUri = 'http://127.0.0.1:8765/callback/',

    [Parameter()]
    [string]$AccessToken,

    [Parameter()]
    [ValidateRange(30, 900)]
    [int]$TimeoutSeconds = 300,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$requiredScope = 'okta.myAccount.webauthn.manage'

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory)][string]$Value)

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    $base64 += '=' * ((4 - ($base64.Length % 4)) % 4)
    [Convert]::FromBase64String($base64)
}

function Get-JwtScopes {
    param([Parameter(Mandatory)][string]$Token)

    try {
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) { return @() }

        $claims = [System.Text.Encoding]::UTF8.GetString(
            (ConvertFrom-Base64Url -Value $parts[1])
        ) | ConvertFrom-Json

        if ($claims.scp -is [string]) { return @($claims.scp -split '\s+') }
        if ($claims.scp) { return @($claims.scp) }
    } catch {
        Write-Verbose 'The supplied access token is not a decodable JWT; scope diagnostics are unavailable.'
    }

    return @()
}

# Normalize the supplied domain and disallow paths or credentials so the bearer token
# cannot accidentally be sent to an unintended endpoint.
$domainInput = $OktaDomain.Trim()
if ($domainInput -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
    $domainUri = [Uri]$domainInput
} else {
    $domainUri = [Uri]("https://$domainInput")
}
if (-not $domainUri.Host -or $domainUri.AbsolutePath -ne '/' -or $domainUri.Query -or $domainUri.Fragment -or $domainUri.UserInfo) {
    throw 'OktaDomain must be a host name only, such as contoso.okta.com.'
}
$oktaOrigin = "https://$($domainUri.Host)"

if (-not $AccessToken -and [string]::IsNullOrWhiteSpace($ClientId)) {
    throw 'ClientId is required unless -AccessToken is supplied.'
}

if (-not $AccessToken) {
    $redirect = [Uri]$RedirectUri
    if ($redirect.Scheme -ne 'http' -or $redirect.Host -notin @('127.0.0.1', 'localhost') -or -not $RedirectUri.EndsWith('/')) {
        throw 'RedirectUri must be an HTTP loopback URI ending in / and must exactly match the OIDC application configuration.'
    }

    $verifierBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $codeVerifier = ConvertTo-Base64Url -Bytes $verifierBytes
    $challenge = ConvertTo-Base64Url -Bytes ([System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::ASCII.GetBytes($codeVerifier)
    ))

    $stateBytes = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
    $expectedState = ConvertTo-Base64Url -Bytes $stateBytes
    $requestedScopes = "openid profile $requiredScope"

    $query = [System.Web.HttpUtility]::ParseQueryString([string]::Empty)
    $query['client_id'] = $ClientId
    $query['response_type'] = 'code'
    $query['response_mode'] = 'query'
    $query['redirect_uri'] = $RedirectUri
    $query['scope'] = $requestedScopes
    $query['state'] = $expectedState
    $query['code_challenge'] = $challenge
    $query['code_challenge_method'] = 'S256'
    $authorizationUri = "$oktaOrigin/oauth2/v1/authorize?$query"

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($RedirectUri)
    try {
        $listener.Start()
        Write-Host 'Open this URL in a browser and complete the Okta sign-in:' -ForegroundColor Cyan
        Write-Host $authorizationUri -ForegroundColor Gray
        Write-Host "Waiting up to $TimeoutSeconds seconds for the loopback redirect..." -ForegroundColor Yellow

        $contextTask = $listener.GetContextAsync()
        if (-not $contextTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            throw 'Timed out waiting for the OAuth redirect.'
        }

        $context = $contextTask.Result
        $parameters = $context.Request.QueryString
        $html = '<!doctype html><title>Okta authorization complete</title><p>You can close this window and return to PowerShell.</p>'
        $htmlBytes = [System.Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentType = 'text/html; charset=utf-8'
        $context.Response.StatusCode = 200
        $context.Response.OutputStream.Write($htmlBytes, 0, $htmlBytes.Length)
        $context.Response.Close()

        if ($parameters['error']) {
            throw "Okta authorization failed: $($parameters['error']) $($parameters['error_description'])"
        }
        if ($parameters['state'] -cne $expectedState) {
            throw 'OAuth state validation failed.'
        }
        if ([string]::IsNullOrWhiteSpace($parameters['code'])) {
            throw 'Okta did not return an authorization code.'
        }

        $tokenBody = @{
            grant_type    = 'authorization_code'
            client_id     = $ClientId
            code          = $parameters['code']
            redirect_uri  = $RedirectUri
            code_verifier = $codeVerifier
        }
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "$oktaOrigin/oauth2/v1/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $tokenBody
        $AccessToken = $tokenResponse.access_token
        $grantedScopes = @($tokenResponse.scope -split '\s+')
    } finally {
        if ($listener.IsListening) { $listener.Stop() }
        $listener.Close()
    }
} else {
    $grantedScopes = Get-JwtScopes -Token $AccessToken
}

if ($grantedScopes.Count -gt 0 -and $requiredScope -notin $grantedScopes) {
    throw "The access token does not contain '$requiredScope'. Grant that scope on the OIDC application's Okta API Scopes tab, request it during authorization, and obtain a new token."
}
if ($grantedScopes.Count -eq 0) {
    Write-Warning "Could not inspect token scopes. The API response is authoritative; it must authorize '$requiredScope'."
}

$headers = @{
    Authorization = "Bearer $AccessToken"
    Accept        = 'application/json; okta-version=1.0.0'
    'Content-Type'= 'application/json'
}

try {
    $registration = Invoke-RestMethod -Method Post -Uri "$oktaOrigin/idp/myaccount/webauthn/registration" -Headers $headers
} catch {
    $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
    throw "Okta registration-start call failed. HTTP/API detail: $detail"
}

if (-not $registration.options.challenge -or -not $registration.expiresAt) {
    throw 'Okta returned an unexpected registration-start response.'
}

$algorithms = @($registration.options.pubKeyCredParams | ForEach-Object { $_.alg }) -join ', '
Write-Host '✓ Okta accepted the user token and issued a short-lived WebAuthn registration challenge.' -ForegroundColor Green
Write-Host "  Origin: $oktaOrigin" -ForegroundColor Gray
Write-Host "  Expires: $($registration.expiresAt)" -ForegroundColor Gray
Write-Host "  Algorithms: $algorithms" -ForegroundColor Gray
Write-Host "  User verification: $($registration.options.authenticatorSelection.userVerification)" -ForegroundColor Gray

if ($PassThru) {
    $registration
}
