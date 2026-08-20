#Requires -Version 7.0

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidGlobalVars',
    '',
    Justification = 'The wrapped reference login script exposes its ESTS cookie and WebRequestSession through documented global variables; this script restores both values in finally.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$KeyFilePath,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$TenantId = 'organizations',

    [Parameter()]
    [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [Parameter()]
    [string]$RedirectUri = 'msauth.com.msauth.unsignedapp://auth',

    [Parameter()]
    [string[]]$Scope = @('https://graph.microsoft.com/.default', 'openid', 'profile', 'offline_access'),

    [Parameter()]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$KeyVaultTenantId,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
$passkeyLoginScriptPath = Join-Path $repoRoot 'powershell\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1'
$passkeyCommonModulePath = Join-Path $repoRoot 'powershell\modules\Passkey.Common\Passkey.Common.psm1'
Import-Module $passkeyCommonModulePath -Force

function Get-AuthorizeUrl {
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Prompt,
        [string]$CodeChallenge,
        [string]$State
    )

    $fields = [ordered]@{
        client_id             = $ClientId
        response_type         = 'code'
        redirect_uri          = $RedirectUri
        response_mode         = 'query'
        scope                 = $Scope
        prompt                = $Prompt
        code_challenge        = $CodeChallenge
        code_challenge_method = $(if ($CodeChallenge) { 'S256' } else { $null })
        state                 = $State
    }
    $query = ($fields.GetEnumerator() |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Value) } |
        ForEach-Object { "$([Uri]::EscapeDataString([string]$_.Key))=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
    return "https://login.microsoftonline.com/$Authority/oauth2/v2.0/authorize?$query"
}

function Get-PkcePair {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $verifier = ConvertTo-Base64Url -Bytes $bytes
    $challenge = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))
    return [PSCustomObject]@{
        Verifier  = $verifier
        Challenge = ConvertTo-Base64Url -Bytes $challenge
    }
}

function Resolve-AbsoluteUri {
    param([Parameter(Mandatory)][string]$BaseUri, [Parameter(Mandatory)][string]$Location)

    $absolute = $null
    if ([Uri]::TryCreate($Location, [UriKind]::Absolute, [ref]$absolute)) {
        return $absolute.AbsoluteUri
    }
    return ([Uri]::new([Uri]$BaseUri, $Location)).AbsoluteUri
}

function ConvertTo-FormBody {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Fields)

    return ($Fields.GetEnumerator() |
        Where-Object { $null -ne $_.Value } |
        ForEach-Object { "$([Uri]::EscapeDataString([string]$_.Key))=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
}

function Get-CodeOrError {
    param([Parameter(Mandatory)][string]$Location)

    $uri = [Uri]$Location
    $candidate = if ($uri.Fragment) { $uri.Fragment.TrimStart('#') } else { $uri.Query.TrimStart('?') }
    $values = [Web.HttpUtility]::ParseQueryString($candidate)
    if ($values['code']) {
        return [PSCustomObject]@{ Code = $values['code']; Error = $null }
    }
    if ($values['error']) {
        return [PSCustomObject]@{
            Code  = $null
            Error = "$($values['error']) - $($values['error_description'])".TrimEnd(' ', '-')
        }
    }
    return [PSCustomObject]@{ Code = $null; Error = $null }
}

function Get-CodeFromEstsCookie {
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$CodeChallenge,
        [Parameter(Mandatory)][string]$EstsCookie,
        [int]$MaxRedirects = 10
    )

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    foreach ($name in @('ESTSAUTH', 'ESTSAUTHPERSISTENT')) {
        $session.Cookies.Add([Net.Cookie]::new($name, $EstsCookie, '/', '.login.microsoftonline.com'))
    }

    $currentUrl = Get-AuthorizeUrl `
        -Authority $Authority `
        -ClientId $ClientId `
        -RedirectUri $RedirectUri `
        -Scope $Scope `
        -Prompt 'none' `
        -CodeChallenge $CodeChallenge `
        -State ([guid]::NewGuid().ToString())
    $currentMethod = 'GET'
    $currentBody = $null

    for ($step = 0; $step -lt $MaxRedirects; $step++) {
        try {
            $parameters = @{
                Uri                = $currentUrl
                Method             = $currentMethod
                WebSession         = $session
                MaximumRedirection = 0
                UseBasicParsing    = $true
            }
            if ($currentMethod -eq 'POST') {
                $parameters.Body = $currentBody
                $parameters.ContentType = 'application/x-www-form-urlencoded'
            }

            $response = Invoke-WebRequest @parameters
            if ($response.StatusCode -ne 200) {
                throw "Unexpected silent authorization response: HTTP $($response.StatusCode)."
            }

            $formAction = [regex]::Match($response.Content, 'action="([^"]+)"')
            $hiddenFields = [regex]::Matches($response.Content, '<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"')
            if ($formAction.Success -and $hiddenFields.Count -gt 0) {
                $fields = [ordered]@{}
                foreach ($field in $hiddenFields) {
                    $fields[$field.Groups[1].Value] = [Net.WebUtility]::HtmlDecode($field.Groups[2].Value)
                }
                $currentUrl = Resolve-AbsoluteUri -BaseUri $currentUrl -Location $formAction.Groups[1].Value
                $currentMethod = 'POST'
                $currentBody = ConvertTo-FormBody -Fields $fields
                continue
            }

            $configMatch = [regex]::Match($response.Content, '\$Config=(\{.*?\});', 'Singleline')
            $pageId = if ($configMatch.Success) { ($configMatch.Groups[1].Value | ConvertFrom-Json).pgid } else { 'unknown' }
            throw "Silent authorization returned page '$pageId' instead of a redirect."
        } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            $status = [int]$_.Exception.Response.StatusCode
            if ($status -lt 300 -or $status -ge 400) { throw }
            $locationHeader = $_.Exception.Response.Headers.Location
            if (-not $locationHeader) { throw 'Redirect response did not include a Location header.' }
            $location = Resolve-AbsoluteUri -BaseUri $currentUrl -Location $locationHeader.ToString()
            $result = Get-CodeOrError -Location $location
            if ($result.Code) {
                return [PSCustomObject]@{ Code = $result.Code; Session = $session }
            }
            if ($result.Error) { throw "Silent authorization failed: $($result.Error)" }
            $currentUrl = $location
            $currentMethod = 'GET'
            $currentBody = $null
        }
    }
    throw "Silent authorization exceeded $MaxRedirects redirect steps."
}

function Get-JwtClaimSet {
    param([Parameter(Mandatory)][string]$Token)

    $parts = $Token.Split('.')
    if ($parts.Length -lt 2) { throw 'Token did not contain a JWT payload.' }
    $json = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url -Base64Url $parts[1]))
    return $json | ConvertFrom-Json
}

function Get-CookieSummary {
    param([Microsoft.PowerShell.Commands.WebRequestSession[]]$Sessions)

    $seen = [Collections.Generic.HashSet[string]]::new()
    $results = [Collections.Generic.List[object]]::new()
    foreach ($session in $Sessions) {
        if ($null -eq $session) { continue }
        foreach ($uri in @('https://login.microsoftonline.com', 'https://mysignins.microsoft.com')) {
            foreach ($cookie in $session.Cookies.GetCookies($uri)) {
                $key = "$($cookie.Domain)|$($cookie.Name)"
                if ($seen.Add($key)) {
                    $results.Add([PSCustomObject]@{
                        name   = $cookie.Name
                        domain = $cookie.Domain
                        length = $cookie.Value.Length
                    })
                }
            }
        }
    }
    return $results | Sort-Object domain, name
}

function Get-TokenSummary {
    param([string]$Token)
    return [PSCustomObject]@{ present = -not [string]::IsNullOrWhiteSpace($Token); length = $Token.Length }
}

$scopeText = $Scope -join ' '
$previousEsts = Get-Variable -Scope Global -Name ESTSAUTH -ErrorAction SilentlyContinue
$previousSession = Get-Variable -Scope Global -Name webSession -ErrorAction SilentlyContinue

try {
    $loginParameters = @{
        KeyFilePath = $KeyFilePath
        AuthUrl     = Get-AuthorizeUrl -Authority $TenantId -ClientId $ClientId -RedirectUri $RedirectUri -Scope $scopeText -Prompt 'login'
        PassThru    = $true
    }
    if ($UserPrincipalName) { $loginParameters.UserPrincipalName = $UserPrincipalName }
    if ($KeyVaultName) { $loginParameters.KeyVaultName = $KeyVaultName }
    if ($KeyVaultKeyName) { $loginParameters.KeyVaultKeyName = $KeyVaultKeyName }
    if ($KeyVaultTenantId) { $loginParameters.KeyVaultTenantId = $KeyVaultTenantId }

    $loginResult = & $passkeyLoginScriptPath @loginParameters 6>$null
    $estsCookie = $global:ESTSAUTH
    $loginSession = $global:webSession
    if (-not $loginResult.Success -or [string]::IsNullOrWhiteSpace($estsCookie)) {
        throw 'Passkey authentication did not return an ESTS session cookie.'
    }

    $pkce = Get-PkcePair
    $authorization = Get-CodeFromEstsCookie `
        -Authority $TenantId `
        -ClientId $ClientId `
        -RedirectUri $RedirectUri `
        -Scope $scopeText `
        -CodeChallenge $pkce.Challenge `
        -EstsCookie $estsCookie

    $tokens = Invoke-RestMethod `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body (ConvertTo-FormBody -Fields @{
            client_id    = $ClientId
            scope        = $scopeText
            grant_type   = 'authorization_code'
            code         = $authorization.Code
            redirect_uri = $RedirectUri
            code_verifier = $pkce.Verifier
        })

    if (-not $tokens.access_token) { throw 'Token exchange did not return an access token.' }
    $accessClaims = Get-JwtClaimSet -Token $tokens.access_token
    $idClaims = if ($tokens.id_token) { Get-JwtClaimSet -Token $tokens.id_token } else { $null }
    $result = [PSCustomObject]@{
        success           = $true
        tenantId          = if ($accessClaims.tid) { $accessClaims.tid } else { $TenantId }
        userPrincipalName = if ($accessClaims.preferred_username) { $accessClaims.preferred_username } else { $loginResult.UserPrincipalName }
        clientId          = $ClientId
        scopesRequested   = $Scope
        passkey           = [PSCustomObject]@{
            credentialFile = [IO.Path]::GetFileName($KeyFilePath)
            signatureMethod = $loginResult.SignatureMethod
            keyVaultName = $loginResult.KeyVaultName
        }
        cookies           = @(Get-CookieSummary -Sessions @($loginSession, $authorization.Session))
        accessToken       = [PSCustomObject]@{
            metadata  = Get-TokenSummary -Token $tokens.access_token
            scope     = $tokens.scope
            tokenType = $tokens.token_type
            expiresIn = $tokens.expires_in
            claims    = $accessClaims
        }
        idToken           = [PSCustomObject]@{
            metadata = Get-TokenSummary -Token $tokens.id_token
            claims   = $idClaims
        }
        refreshToken      = Get-TokenSummary -Token $tokens.refresh_token
    }

    if ($PassThru) { $result } else { $result | ConvertTo-Json -Depth 8 }
} finally {
    if ($previousEsts) { $global:ESTSAUTH = $previousEsts.Value }
    else { Remove-Variable -Scope Global -Name ESTSAUTH -ErrorAction SilentlyContinue }
    if ($previousSession) { $global:webSession = $previousSession.Value }
    else { Remove-Variable -Scope Global -Name webSession -ErrorAction SilentlyContinue }
}
