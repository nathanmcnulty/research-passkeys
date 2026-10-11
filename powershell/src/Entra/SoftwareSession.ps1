# Shared My Sign-ins registration transport and request state. Loading this file has no side effects.
function Assert-EntraRegistrationUri {
    param([Parameter(Mandatory)][string]$Uri)
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or $parsed.Port -ne 443 -or $parsed.UserInfo -or
        $parsed.Host -notin @('login.microsoftonline.com', 'login.microsoft.com', 'mysignins.microsoft.com')) {
        throw 'Registration endpoint is outside the allowed HTTPS origins.'
    }
    return $parsed
}

function Invoke-EntraRegistrationWebRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', $Body,
        [string]$ContentType, [hashtable]$Headers, $WebSession)
    $null = Assert-EntraRegistrationUri $Uri
    $request = @{} + $PSBoundParameters
    $request.Headers = if ($null -ne $Headers) { @{} + $Headers } else { @{} }
    if ($null -ne $WebSession -and $WebSession.UserAgent) { $request.Headers['User-Agent'] = $WebSession.UserAgent }
    Add-PasskeyBrowserHeaders -Headers $request.Headers
    $request.MaximumRedirection = 0
    $request.SkipHttpErrorCheck = $true
    $request.ConnectionTimeoutSeconds = 60
    $request.OperationTimeoutSeconds = 60
    $request.Verbose = $false
    $request.Debug = $false
    # No automatic redirects: authentication data must stay on the checked origin.
    Microsoft.PowerShell.Utility\Invoke-WebRequest @request
}

function Invoke-EntraRegistrationRestMethod {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', $Body,
        [string]$ContentType, [hashtable]$Headers, $WebSession)
    $response = Invoke-EntraRegistrationWebRequest @PSBoundParameters
    if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw 'Registration request was not successful; response details suppressed.'
    }
    try { return ($response.Content | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw 'Registration endpoint returned an invalid JSON response.' }
}

function ConvertTo-EntraRegistrationForm {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Fields)
    return (($Fields.GetEnumerator() | ForEach-Object {
        [Web.HttpUtility]::UrlEncode([string]$_.Key) + '=' + [Web.HttpUtility]::UrlEncode([string]$_.Value)
    }) -join '&')
}

function Get-EntraRegistrationPageConfig {
    param([Parameter(Mandatory)][string]$Content)
    if ($Content -notmatch '(?s)\$Config\s*=\s*(\{.*?\});') { throw 'Registration page configuration is missing.' }
    try { return ($matches[1] | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw 'Registration page configuration is invalid.' }
}

function Get-EntraRegistrationAuthorizationCode {
    param([Parameter(Mandatory)][string]$Callback, [Parameter(Mandatory)][string]$ExpectedState)
    $uri = Assert-EntraRegistrationUri $Callback
    if ($uri.Host -ne 'mysignins.microsoft.com' -or $uri.AbsolutePath -ne '/') { throw 'Unexpected authorization callback.' }
    $fields = [Web.HttpUtility]::ParseQueryString(($uri.Query.TrimStart('?') + '&' + $uri.Fragment.TrimStart('#')))
    $states = @($fields.GetValues('state')); $codes = @($fields.GetValues('code'))
    if ($states.Count -ne 1 -or $states[0] -cne $ExpectedState -or $codes.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($codes[0]) -or $fields['error']) {
        throw 'Missing, ambiguous or mismatched authorization response.'
    }
    return $codes[0]
}

function New-EntraRegistrationContext {
    param([string]$RedirectUri = 'https://mysignins.microsoft.com', [string]$UserAgent)
    if ($RedirectUri.TrimEnd('/') -cne 'https://mysignins.microsoft.com') { throw 'Registration RedirectUri must be https://mysignins.microsoft.com.' }
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    if ($UserAgent) { $session.UserAgent = $UserAgent }
    $random = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($random)
    $verifier = ConvertTo-Base64Url $random
    [pscustomobject]@{
        ClientId = '19db86c3-b2b9-44cc-b339-36da233a3be2'
        RedirectUri = $RedirectUri.TrimEnd('/')
        State = [guid]::NewGuid().ToString()
        CodeVerifier = $verifier
        CodeChallenge = ConvertTo-Base64Url ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
        WebSession = $session
        ClientSessionId = [guid]::NewGuid().ToString()
        TenantId = $null; UserPrincipalName = $null; Token = $null; RefreshToken = $null; SessionCtxV2 = $null
    }
}

function Get-EntraRegistrationHeaders {
    param([Parameter(Mandatory)]$Context, [switch]$IncludeToken, [switch]$IncludeSession)
    $headers = @{
        Origin = $Context.RedirectUri; Referer = "$($Context.RedirectUri)/security-info"
        AjaxRequest = 'true'; 'x-ms-mysignins-region' = 'westus2'
        'x-ms-client-session-id' = $Context.ClientSessionId
    }
    if ($IncludeToken) { $headers.Authorization = "Bearer $($Context.Token)" }
    if ($IncludeSession) { $headers.SessionCtxV2 = $Context.SessionCtxV2 }
    if ($Context.WebSession -and $Context.WebSession.UserAgent) { $headers['User-Agent'] = $Context.WebSession.UserAgent }
    Add-PasskeyBrowserHeaders -Headers $headers
    return $headers
}

function Initialize-EntraRegistrationSession {
    param([Parameter(Mandatory)]$Context)
    $headers = Get-EntraRegistrationHeaders -Context $Context -IncludeToken
    $response = Invoke-EntraRegistrationRestMethod -Uri "$($Context.RedirectUri)/api/session/authorize" `
        -Method POST -Headers $headers -ContentType 'application/json' -Body '{}' -WebSession $Context.WebSession
    if ($response.isAuthorized -ne $true -or [string]::IsNullOrWhiteSpace($response.sessionCtxV2)) {
        throw 'My Sign-ins registration session was not authorized.'
    }
    if ($response.requireNgcMfaForSecurityInfo) {
        $claims = '{"id_token":{"amr":{"essential":true,"values":["ngcmfa"]}},"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}'
        $body = ConvertTo-EntraRegistrationForm @{
            client_id = $Context.ClientId; scope = "$($Context.ClientId)/.default openid"
            grant_type = 'refresh_token'; refresh_token = $Context.RefreshToken; claims = $claims
        }
        $tokens = Invoke-EntraRegistrationRestMethod -Uri "https://login.microsoftonline.com/$($Context.TenantId)/oauth2/v2.0/token" `
            -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -Headers @{ Origin = $Context.RedirectUri }
        $null = Assert-EntraRegistrationTokenBinding -Token $tokens.access_token -ClientId $Context.ClientId `
            -TenantId $Context.TenantId -UserPrincipalName $Context.UserPrincipalName
        $Context.Token = $tokens.access_token
        if ($tokens.refresh_token) { $Context.RefreshToken = $tokens.refresh_token }
        $headers.Authorization = "Bearer $($Context.Token)"
        $response = Invoke-EntraRegistrationRestMethod -Uri "$($Context.RedirectUri)/api/session/authorize" `
            -Method POST -Headers $headers -ContentType 'application/json' -Body '{}' -WebSession $Context.WebSession
        if ($response.isAuthorized -ne $true -or [string]::IsNullOrWhiteSpace($response.sessionCtxV2)) {
            throw 'My Sign-ins MFA registration session was not authorized.'
        }
    }
    $Context.SessionCtxV2 = $response.sessionCtxV2
    return $Context
}
