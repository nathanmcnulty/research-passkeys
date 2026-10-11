# Bounded OAuth continuation; only known KMSI pages are eligible for form submission.
function Invoke-EntraRegistrationAuthorization {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET', [AllowNull()][string]$Body)
    $current = $Uri
    for ($step = 0; $step -lt 15; $step++) {
        $request = @{ Uri = $current; Method = $Method; WebSession = $Context.WebSession }
        if ($Method -eq 'POST') { $request.Body = $Body; $request.ContentType = 'application/x-www-form-urlencoded' }
        $response = Invoke-EntraRegistrationWebRequest @request
        $status = [int]$response.StatusCode
        if ($status -in @(301, 302, 303, 307, 308)) {
            $locations = @($response.Headers.Location)
            if ($locations.Count -ne 1 -or [string]::IsNullOrWhiteSpace($locations[0])) { throw 'Missing or ambiguous registration redirect.' }
            $next = [uri]::new([uri]$current, [string]$locations[0]).AbsoluteUri
            $nextUri = Assert-EntraRegistrationUri $next
            $fields = [Web.HttpUtility]::ParseQueryString($nextUri.Query.TrimStart('?') + '&' + $nextUri.Fragment.TrimStart('#'))
            if ($fields['code'] -or $fields['error']) {
                return Get-EntraRegistrationAuthorizationCode -Callback $next -ExpectedState $Context.State
            }
            # Do not forward a TAP/form through 307/308 or to another origin.
            if ($status -in @(307, 308) -and $Method -eq 'POST') {
                if ($nextUri.Host -ne ([uri]$current).Host) { throw 'Cross-origin registration form redirect refused.' }
            } else { $Method = 'GET'; $Body = $null }
            $current = $next
            continue
        }
        if ($status -ne 200) { throw 'Registration authorization was not successful.' }
        $config = Get-EntraRegistrationPageConfig -Content $response.Content
        if ($config.pgid -notin @('KmsiBroker', 'KmsiInterrupt') -or $config.strServiceExceptionMessage) {
            throw 'Unrecognized login continuation or consent interrupt; manual review required.'
        }
        $actions = [regex]::Matches($response.Content, '(?is)<form\b[^>]*\baction="([^"]+)"')
        if ($actions.Count -ne 1) { throw 'Registration continuation form is missing or ambiguous.' }
        $nextUri = Assert-EntraRegistrationUri ([uri]::new([uri]$current, [Web.HttpUtility]::HtmlDecode($actions[0].Groups[1].Value)).AbsoluteUri)
        if ($nextUri.Host -ne 'login.microsoftonline.com') { throw 'Unexpected registration continuation destination.' }
        $fields = [ordered]@{}
        foreach ($input in [regex]::Matches($response.Content, '(?is)<input\b[^>]*>')) {
            $tag = $input.Value
            if ($tag -notmatch '\btype="hidden"' -or $tag -notmatch '\bname="([^"]+)"') { continue }
            $name = [Web.HttpUtility]::HtmlDecode($matches[1])
            if ($tag -notmatch '\bvalue="([^"]*)"') { throw 'Registration continuation field has no value.' }
            if ($fields.Contains($name)) { throw 'Duplicate registration continuation field.' }
            $fields[$name] = [Web.HttpUtility]::HtmlDecode($matches[1])
        }
        if (-not $fields.Count) { throw 'Registration continuation has no hidden fields.' }
        $current = $nextUri.AbsoluteUri; $Method = 'POST'; $Body = ConvertTo-EntraRegistrationForm $fields
    }
    throw 'Registration authorization exceeded the redirect limit.'
}

function Assert-EntraRegistrationTokenBinding {
    param([Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$ClientId,
        [AllowNull()][string]$TenantId, [AllowNull()][string]$UserPrincipalName)
    # These transport-returned claims are consistency checks, not independent signature validation.
    $parts = $Token.Split('.')
    if ($parts.Count -ne 3) { throw 'Registration token is malformed.' }
    try { $claims = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Registration token claims are invalid.' }
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse([string]$claims.tid, [ref]$tenant) -or $tenant -eq [guid]::Empty -or
        [string]$claims.aud -cne $ClientId) { throw 'Registration token audience or tenant is not bound to the requested client.' }
    foreach ($property in @('appid', 'azp')) {
        $value = $claims.PSObject.Properties[$property]
        if ($null -ne $value -and $value.Value -and [string]$value.Value -cne $ClientId) { throw 'Registration token application binding mismatch.' }
    }
    if ($TenantId -and $tenant -ne [guid]$TenantId) { throw 'Registration token tenant mismatch.' }
    $upn = $claims.upn
    if (-not $upn) { $upn = $claims.preferred_username }
    if (-not $upn) { $upn = $claims.unique_name }
    if ([string]$upn -notmatch '^[^\s@]+@[^\s@]+$' -or ($UserPrincipalName -and $upn -ine $UserPrincipalName)) {
        throw 'Registration token user binding mismatch.'
    }
    if ($null -eq $claims.exp -or [long]$claims.exp -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { throw 'Registration token has expired or has no expiry.' }
    return [pscustomobject]@{ TenantId = $tenant.ToString(); UserPrincipalName = [string]$upn }
}

function Get-EntraRegistrationAuthorizeUri {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Authority,
        [AllowNull()][string]$UserPrincipalName, [switch]$Tap)
    $query = [ordered]@{
        client_id = $Context.ClientId; redirect_uri = $Context.RedirectUri
        scope = "$($Context.ClientId)/.default openid profile offline_access"
        response_type = 'code'; response_mode = 'fragment'; code_challenge = $Context.CodeChallenge
        code_challenge_method = 'S256'; state = $Context.State
    }
    if ($Tap) { $query.prompt = 'login'; $query.login_hint = $UserPrincipalName }
    else { $query.prompt = 'none' }
    return "https://login.microsoftonline.com/$Authority/oauth2/v2.0/authorize?$(ConvertTo-EntraRegistrationForm $query)"
}

function Complete-EntraRegistrationTokenExchange {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$Code, [AllowNull()][string]$TenantId, [AllowNull()][string]$UserPrincipalName)
    $body = ConvertTo-EntraRegistrationForm @{
        client_id = $Context.ClientId; redirect_uri = $Context.RedirectUri
        scope = "$($Context.ClientId)/.default openid profile offline_access"
        grant_type = 'authorization_code'; code = $Code; code_verifier = $Context.CodeVerifier
        # Preserve the curated TAP bootstrap: request required MFA claims on the initial exchange.
        claims = '{"id_token":{"amr":{"essential":true,"values":["ngcmfa"]}},"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}'
    }
    $tokens = Invoke-EntraRegistrationRestMethod -Uri "https://login.microsoftonline.com/$Authority/oauth2/v2.0/token" `
        -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -Headers @{ Origin = $Context.RedirectUri }
    if ([string]::IsNullOrWhiteSpace($tokens.refresh_token)) { throw 'Registration refresh token is missing.' }
    $identity = Assert-EntraRegistrationTokenBinding -Token $tokens.access_token -ClientId $Context.ClientId `
        -TenantId $TenantId -UserPrincipalName $UserPrincipalName
    $Context.Token = $tokens.access_token; $Context.RefreshToken = $tokens.refresh_token
    $Context.TenantId = $identity.TenantId; $Context.UserPrincipalName = $identity.UserPrincipalName
    $Context.CodeVerifier = $null
    return $Context
}
