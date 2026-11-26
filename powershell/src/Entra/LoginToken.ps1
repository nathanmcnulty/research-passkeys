function Assert-EntraTokenUri {
    param([Parameter(Mandatory)][string]$Uri)
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne 'https' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Host -notin @('login.microsoftonline.com', 'login.microsoft.com', 'login.windows.net')) {
        throw 'Untrusted Entra token or device-login URL.'
    }
    return $parsed
}

function Invoke-EntraTokenHttpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [AllowNull()][string]$Body,
        [string]$ContentType = 'application/x-www-form-urlencoded',
        [AllowNull()][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy,
        [AllowNull()][hashtable]$Headers
    )
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    if ($null -ne $WebSession) {
        $handler.UseCookies = $true
        $handler.CookieContainer = $WebSession.Cookies
    } else {
        $handler.UseCookies = $false
    }
    if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
        $handler.UseProxy = $true
        $handler.Proxy = [System.Net.WebProxy]::new($Proxy)
    }
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $request = $null
    $response = $null
    try {
        $effectiveUserAgent = if ($null -ne $WebSession -and -not [string]::IsNullOrWhiteSpace($WebSession.UserAgent)) {
            $WebSession.UserAgent
        } else {
            $UserAgent
        }
        if (-not [string]::IsNullOrWhiteSpace($effectiveUserAgent)) {
            $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', $effectiveUserAgent)
        }
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant()), $Uri)
        if ($null -ne $Headers) {
            foreach ($entry in $Headers.GetEnumerator()) {
                $null = $request.Headers.TryAddWithoutValidation([string]$entry.Key, [string]$entry.Value)
            }
        }
        if ($null -ne $Body) {
            $request.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, $ContentType)
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $location = if ($response.Headers.Location) { $response.Headers.Location.OriginalString } else { $null }
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Location   = $location
            Content    = $content
        }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}

function ConvertTo-EntraFormEncodedBody {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Fields)
    $pairs = foreach ($entry in $Fields.GetEnumerator()) {
        if ($null -ne $entry.Value) {
            [System.Web.HttpUtility]::UrlEncode([string]$entry.Key) + '=' + [System.Web.HttpUtility]::UrlEncode([string]$entry.Value)
        }
    }
    return ($pairs -join '&')
}

function New-EntraPkceChallenge {
    $random = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
    $verifier = ConvertTo-Base64Url $random
    $challenge = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($verifier)))
    return @{
        Verifier  = $verifier
        Challenge = $challenge
        State     = [guid]::NewGuid().ToString('N')
    }
}

function Test-EntraPasskeyTenantIdFormat {
    param([AllowNull()][string]$TenantId)
    $trimmedTenant = Normalize-OptionalString $TenantId
    if (-not $trimmedTenant) {
        return $null
    }
    if ($trimmedTenant.ToLowerInvariant() -in @('organizations', 'common', 'consumers')) {
        return $trimmedTenant.ToLowerInvariant()
    }
    $parsedTenant = [guid]::Empty
    if (-not [guid]::TryParse($trimmedTenant, [ref]$parsedTenant) -or $parsedTenant -eq [guid]::Empty) {
        throw 'TenantId must be a nonempty GUID or one of organizations, common, consumers.'
    }
    return $parsedTenant.ToString()
}

function Resolve-EntraPasskeyAuthority {
    param(
        [AllowNull()][string]$TenantId,
        [AllowNull()][string]$UserPrincipalName,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy
    )
    $validatedTenant = Test-EntraPasskeyTenantIdFormat -TenantId $TenantId
    if ($validatedTenant) {
        return $validatedTenant
    }

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -or $UserPrincipalName -notmatch '^[^\s@]+@([^\s@]+)$') {
        throw 'A valid UserPrincipalName or explicit TenantId is required to resolve the Entra authority.'
    }
    $domain = $Matches[1]
    if ([uri]::CheckHostName($domain) -ne [UriHostNameType]::Dns -or $domain.Contains('%')) {
        throw 'UserPrincipalName domain suffix must be a valid DNS name.'
    }
    $discoveryUri = "https://login.microsoftonline.com/$([uri]::EscapeDataString($domain))/v2.0/.well-known/openid-configuration"
    $null = Assert-EntraTokenUri $discoveryUri
    $response = Invoke-EntraTokenHttpRequest -Uri $discoveryUri -Method 'GET' -UserAgent $UserAgent -Proxy $Proxy
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw "Tenant OIDC discovery failed with HTTP $($response.StatusCode)."
    }
    $metadata = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    $issuer = Assert-EntraTokenUri ([string]$metadata.issuer)
    $resolvedGuid = [guid]::Empty
    $firstSegment = $issuer.AbsolutePath.Trim('/').Split('/')[0]
    if (-not [guid]::TryParse($firstSegment, [ref]$resolvedGuid) -or $resolvedGuid -eq [guid]::Empty -or
        $issuer.Host -ne 'login.microsoftonline.com' -or $issuer.AbsolutePath -cne "/$($resolvedGuid.ToString())/v2.0") {
        throw 'Tenant discovery did not return a valid Microsoft Entra tenant GUID issuer.'
    }
    return $resolvedGuid.ToString()
}

function Resolve-EntraPasskeyScopes {
    param(
        [AllowNull()][string[]]$Scope,
        [switch]$IncludeRefreshToken
    )
    $list = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Scope) {
        foreach ($entry in $Scope) {
            foreach ($part in ([string]$entry -split '\s+')) {
                $trimmed = $part.Trim()
                if ($trimmed -and $seen.Add($trimmed)) {
                    $list.Add($trimmed)
                }
            }
        }
    }
    if ($list.Count -eq 0) {
        $null = $seen.Add('https://graph.microsoft.com/.default')
        $list.Add('https://graph.microsoft.com/.default')
    }
    if ($IncludeRefreshToken -and $seen.Add('offline_access')) {
        $list.Add('offline_access')
    }
    return @($list)
}

function Read-EntraTokenPageConfig {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    if ($Content.Length -gt 2097152) {
        throw 'Entra returned an oversized response.'
    }
    $start = -1
    $configMatch = [regex]::Match($Content, '\$Config\s*=\s*\{')
    if ($configMatch.Success) {
        $start = $configMatch.Index + $configMatch.Length - 1
    } elseif ($Content.TrimStart().StartsWith('{')) {
        $start = $Content.IndexOf('{')
    }
    if ($start -lt 0) {
        return $null
    }
    $depth = 0
    $inString = $false
    $escaped = $false
    $end = -1
    for ($index = $start; $index -lt $Content.Length; $index++) {
        $character = $Content[$index]
        if ($inString) {
            if ($escaped) { $escaped = $false }
            elseif ($character -eq '\') { $escaped = $true }
            elseif ($character -eq '"') { $inString = $false }
        } elseif ($character -eq '"') {
            $inString = $true
        } elseif ($character -eq '{') {
            $depth++
        } elseif ($character -eq '}') {
            $depth--
            if ($depth -eq 0) { $end = $index; break }
        }
    }
    if ($end -lt 0) {
        throw 'Entra returned malformed configuration JSON.'
    }
    try {
        $state = $Content.Substring($start, $end - $start + 1) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    } catch {
        throw 'Entra returned malformed configuration JSON.'
    }
    if ($state -isnot [System.Collections.IDictionary]) {
        throw 'Entra returned invalid configuration.'
    }
    return $state
}

function Test-EntraRedirectUriMatch {
    param(
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$RedirectUri
    )
    $normalizedBase = $RedirectUri.TrimEnd('/')
    if ($Location.Equals($normalizedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    if ($Location.StartsWith($normalizedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        $nextChar = $Location[$normalizedBase.Length]
        return ($nextChar -in @('/', '?', '#'))
    }
    return $false
}

function Get-EntraRedirectCallbackCode {
    param(
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$ExpectedState
    )
    $parsed = $null
    if (-not [uri]::TryCreate($Location, [UriKind]::Absolute, [ref]$parsed)) {
        throw 'Authorization callback location is not a valid URI.'
    }
    $combined = ($parsed.Query.TrimStart('?') + '&' + $parsed.Fragment.TrimStart('#')).Trim('&')
    $fields = [System.Web.HttpUtility]::ParseQueryString($combined)
    if ($fields['error']) {
        $description = $fields['error_description']
        throw "Authorization failed: $($fields['error']) $description".Trim()
    }
    $states = @($fields.GetValues('state'))
    $codes = @($fields.GetValues('code'))
    if ($states.Count -ne 1 -or $states[0] -cne $ExpectedState -or $codes.Count -ne 1 -or [string]::IsNullOrWhiteSpace($codes[0])) {
        throw 'Authorization callback was missing a valid code or state.'
    }
    return [string]$codes[0]
}

function Invoke-EntraInterruptStep {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$CurrentUri,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy,
        [switch]$AllowRemoteConnectCmsi
    )
    $pageId = [string]$Config.pgid
    $allowedCmsi = if ($AllowRemoteConnectCmsi) { @('CmsiInterrupt', 'RemoteConnectCmsi') } else { @('CmsiInterrupt') }
    if ($pageId -in $allowedCmsi) {
        foreach ($field in @('canary', 'sFT', 'correlationId', 'sCtx')) {
            if ($Config[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace($Config[$field])) {
                throw "Application confirmation state is missing field '$field'."
            }
        }
        $postRelative = if ($Config.urlPost) { [string]$Config.urlPost } else { '/appverify' }
        $targetUri = ([uri]::new([uri]$CurrentUri, $postRelative)).AbsoluteUri
        $null = Assert-EntraTokenUri $targetUri
        $body = ConvertTo-EntraFormEncodedBody ([ordered]@{
            ContinueAuth    = 'true'
            i19             = (Get-Random -Minimum 1000 -Maximum 9999)
            canary          = $Config.canary
            iscsrfspeedbump = 'false'
            flowToken       = $Config.sFT
            hpgrequestid    = $Config.correlationId
            ctx             = $Config.sCtx
        })
        return [pscustomobject]@{
            Uri      = $targetUri
            Response = (Invoke-EntraTokenHttpRequest -Uri $targetUri -Method 'POST' -Body $body -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy)
        }
    }
    if ($pageId -eq 'KmsiInterrupt') {
        $postRelative = if ($Config.urlPost) { [string]$Config.urlPost } else { '/kmsi' }
        $targetUri = ([uri]::new([uri]$CurrentUri, $postRelative)).AbsoluteUri
        $null = Assert-EntraTokenUri $targetUri
        $body = ConvertTo-EntraFormEncodedBody ([ordered]@{
            LoginOptions = 1
            type         = 28
            ctx          = $Config.sCtx
            hpgrequestid = $Config.correlationId
            flowToken    = $Config.sFT
            canary       = $Config.canary
            i19          = 4130
        })
        return [pscustomobject]@{
            Uri      = $targetUri
            Response = (Invoke-EntraTokenHttpRequest -Uri $targetUri -Method 'POST' -Body $body -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy)
        }
    }
    if ($pageId -eq 'ConvergedSignIn' -and $Config.arrSessions -and @($Config.arrSessions).Count -gt 0 -and $Config.urlLogin) {
        $loginBase = [uri]::new([uri]$CurrentUri, [string]$Config.urlLogin)
        $null = Assert-EntraTokenUri $loginBase.AbsoluteUri
        $sessionId = [string]($Config.arrSessions[0].id ?? $Config.sessionId)
        $separator = if ($loginBase.Query) { '&' } else { '?' }
        $targetUri = $loginBase.AbsoluteUri + $separator + 'sessionid=' + [uri]::EscapeDataString($sessionId)
        return [pscustomobject]@{
            Uri      = $targetUri
            Response = (Invoke-EntraTokenHttpRequest -Uri $targetUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy)
        }
    }
    return $null
}

function Get-EntraAuthorizationCodeFromSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string[]]$Scopes,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][hashtable]$Pkce,
        [AllowNull()][string]$Claims,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy,
        [int]$MaxSteps = 15
    )
    $query = [ordered]@{
        client_id             = $ClientId
        response_type         = 'code'
        redirect_uri          = $RedirectUri
        response_mode         = 'query'
        scope                 = ($Scopes -join ' ')
        login_hint            = $UserPrincipalName
        code_challenge        = $Pkce.Challenge
        code_challenge_method = 'S256'
        state                 = $Pkce.State
    }
    if (-not [string]::IsNullOrWhiteSpace($Claims)) {
        $query.claims = $Claims
    }
    $currentUri = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/authorize?" + (ConvertTo-EntraFormEncodedBody $query)
    $null = Assert-EntraTokenUri $currentUri
    $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy

    $lastPageId = $null
    for ($step = 0; $step -lt $MaxSteps; $step++) {
        if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
            if ([string]::IsNullOrWhiteSpace($response.Location)) {
                throw 'Authorization redirect did not include a Location header.'
            }
            $nextLocation = if ([uri]::IsWellFormedUriString($response.Location, [UriKind]::Absolute)) {
                $response.Location
            } else {
                ([uri]::new([uri]$currentUri, $response.Location)).AbsoluteUri
            }
            if (Test-EntraRedirectUriMatch -Location $nextLocation -RedirectUri $RedirectUri) {
                return Get-EntraRedirectCallbackCode -Location $nextLocation -ExpectedState $Pkce.State
            }
            $null = Assert-EntraTokenUri $nextLocation
            $currentUri = $nextLocation
            $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy
            continue
        }
        if ($response.StatusCode -ne 200) {
            throw "Authorization request failed with HTTP $($response.StatusCode)."
        }
        $config = Read-EntraTokenPageConfig -Content $response.Content
        if (-not $config) {
            throw 'Authorization endpoint returned an unexpected page without $Config.'
        }
        if ($config.strServiceExceptionMessage -or $config.sErrTxt -or $config.error -or $config.errorCode) {
            $detail = $config.strServiceExceptionMessage ?? $config.sErrTxt ?? $config.error ?? $config.errorCode
            throw "Entra authorization failed: $detail"
        }
        $pageId = [string]$config.pgid
        if ($pageId -eq $lastPageId -and $pageId -ne 'ConvergedSignIn') {
            throw "Authorization stuck in interrupt loop on page '$pageId'."
        }
        $lastPageId = $pageId
        $stepResult = Invoke-EntraInterruptStep -Config $config -CurrentUri $currentUri -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy
        if ($null -eq $stepResult) {
            throw "Unsupported or interactive Entra page '$pageId' encountered during token authorization."
        }
        $currentUri = $stepResult.Uri
        $response = $stepResult.Response
    }
    throw 'Authorization exceeded maximum redirect/interrupt steps without returning a code.'
}

function Request-EntraTokenByAuthorizationCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$CodeVerifier,
        [Parameter(Mandatory)][string[]]$Scopes,
        [AllowNull()][string]$Claims,
        [AllowNull()][string]$SpaOrigin,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy
    )
    $tokenUri = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/token"
    $null = Assert-EntraTokenUri $tokenUri
    $fields = [ordered]@{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $Code
        redirect_uri  = $RedirectUri
        code_verifier = $CodeVerifier
        scope         = ($Scopes -join ' ')
    }
    if (-not [string]::IsNullOrWhiteSpace($Claims)) {
        $fields.claims = $Claims
    }
    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($SpaOrigin)) {
        $headers['Origin'] = $SpaOrigin
    }
    $response = Invoke-EntraTokenHttpRequest -Uri $tokenUri -Method 'POST' -Body (ConvertTo-EntraFormEncodedBody $fields) -UserAgent $UserAgent -Proxy $Proxy -Headers $headers
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $errDetail = ''
        try {
            $errJson = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            $errDetail = "$($errJson.error): $($errJson.error_description)"
        } catch {
            $errDetail = "HTTP $($response.StatusCode)"
        }
        throw "Token exchange failed ($errDetail)."
    }
    $payload = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$payload.access_token)) {
        throw 'Token endpoint did not return an access_token.'
    }
    return $payload
}

function Request-EntraDeviceCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string[]]$Scopes,
        [AllowNull()][string]$Claims,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy
    )
    $deviceCodeUri = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/devicecode"
    $null = Assert-EntraTokenUri $deviceCodeUri
    $fields = [ordered]@{
        client_id = $ClientId
        scope     = ($Scopes -join ' ')
    }
    if (-not [string]::IsNullOrWhiteSpace($Claims)) {
        $fields.claims = $Claims
    }
    $response = Invoke-EntraTokenHttpRequest -Uri $deviceCodeUri -Method 'POST' -Body (ConvertTo-EntraFormEncodedBody $fields) -UserAgent $UserAgent -Proxy $Proxy
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $errDetail = ''
        try {
            $errJson = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            $errDetail = "$($errJson.error): $($errJson.error_description)"
        } catch {
            $errDetail = "HTTP $($response.StatusCode)"
        }
        throw "Device code request failed ($errDetail)."
    }
    $payload = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    foreach ($required in @('device_code', 'user_code', 'verification_uri')) {
        if ([string]::IsNullOrWhiteSpace([string]$payload[$required])) {
            throw "Device code response was missing required field '$required'."
        }
    }
    $null = Assert-EntraTokenUri ([string]$payload.verification_uri)
    return $payload
}

function Complete-EntraDeviceCodeWithSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter(Mandatory)][string]$UserCode,
        [string]$VerificationUri = 'https://login.microsoftonline.com/common/oauth2/deviceauth',
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy,
        [int]$MaxSteps = 15
    )
    $normalizedCode = $UserCode.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedCode)) {
        throw 'UserCode cannot be empty.'
    }
    $currentUri = (Assert-EntraTokenUri $VerificationUri).AbsoluteUri
    $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy
    for ($hop = 0; $hop -lt 5 -and $response.StatusCode -in @(301, 302, 303, 307, 308); $hop++) {
        if ([string]::IsNullOrWhiteSpace($response.Location)) {
            throw 'Device verification redirect was missing a Location header.'
        }
        $nextUri = ([uri]::new([uri]$currentUri, $response.Location)).AbsoluteUri
        $currentUri = (Assert-EntraTokenUri $nextUri).AbsoluteUri
        $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy
    }
    if ($response.StatusCode -ne 200) {
        throw "Failed to load device verification page (HTTP $($response.StatusCode))."
    }
    $config = Read-EntraTokenPageConfig -Content $response.Content
    if (-not $config -or [string]$config.pgid -ne 'ConvergedRemoteConnect') {
        $pgid = if ($config) { $config.pgid } else { '<none>' }
        throw "Unexpected device verification page '$pgid'."
    }
    $postUri = ([uri]::new([uri]$currentUri, ([string]($config.urlPost ?? '/common/oauth2/deviceauth')))).AbsoluteUri
    $null = Assert-EntraTokenUri $postUri
    $otcBody = ConvertTo-EntraFormEncodedBody ([ordered]@{
        otc       = $normalizedCode
        canary    = [string]$config.canary
        flowToken = [string]$config.sFT
    })
    $currentUri = $postUri
    $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'POST' -Body $otcBody -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy

    $lastPageId = $null
    for ($step = 0; $step -lt $MaxSteps; $step++) {
        if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
            if ([string]::IsNullOrWhiteSpace($response.Location)) {
                throw 'Device code flow redirect was missing a Location header.'
            }
            $nextUri = ([uri]::new([uri]$currentUri, $response.Location)).AbsoluteUri
            $currentUri = (Assert-EntraTokenUri $nextUri).AbsoluteUri
            $response = Invoke-EntraTokenHttpRequest -Uri $currentUri -Method 'GET' -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy
            continue
        }
        if ($response.StatusCode -ne 200) {
            throw "Device code flow failed with HTTP $($response.StatusCode)."
        }
        $pageConfig = Read-EntraTokenPageConfig -Content $response.Content
        if (-not $pageConfig) {
            throw 'Device code page did not return a $Config block.'
        }
        $pageId = [string]$pageConfig.pgid
        if ($pageConfig.strServiceExceptionMessage -or $pageConfig.sErrTxt -or $pageConfig.error -or $pageConfig.errorCode) {
            $detail = $pageConfig.strServiceExceptionMessage ?? $pageConfig.sErrTxt ?? $pageConfig.error ?? $pageConfig.errorCode
            throw "Device code authentication failed on page '$pageId': $detail"
        }
        if ($pageId -eq 'ConvergedRemoteConnect') {
            $stsErr = [int]($pageConfig.stsErrorCode ?? 0)
            throw "Device user code '$normalizedCode' was rejected (stsErrorCode=$stsErr)."
        }
        if ($pageId -eq 'ConvergedMessage') {
            $stsErr = [int]($pageConfig.stsErrorCode ?? 0)
            if ($stsErr -ne 0) {
                throw "Device code completion returned stsErrorCode=$stsErr."
            }
            return [pscustomobject]@{
                Completed = $true
                AppName   = Normalize-OptionalString ([string]$pageConfig.sRemoteConnectAppName)
            }
        }
        if ($pageId -eq $lastPageId -and $pageId -ne 'ConvergedSignIn') {
            throw "Device code flow stuck in interrupt loop on page '$pageId'."
        }
        $lastPageId = $pageId
        $stepResult = Invoke-EntraInterruptStep -Config $pageConfig -CurrentUri $currentUri -WebSession $WebSession -UserAgent $UserAgent -Proxy $Proxy -AllowRemoteConnectCmsi
        if ($null -eq $stepResult) {
            throw "Unsupported or interactive Entra page '$pageId' encountered during device code completion."
        }
        $currentUri = $stepResult.Uri
        $response = $stepResult.Response
    }
    throw 'Device code completion exceeded maximum steps without reaching confirmation.'
}

function Wait-EntraDeviceCodeToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$DeviceCode,
        [int]$IntervalSeconds = 5,
        [int]$TimeoutSeconds = 900,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy
    )
    $tokenUri = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/token"
    $null = Assert-EntraTokenUri $tokenUri
    $interval = [Math]::Max($IntervalSeconds, 1)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Max($TimeoutSeconds, 10))
    $body = ConvertTo-EntraFormEncodedBody ([ordered]@{
        client_id   = $ClientId
        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
        device_code = $DeviceCode
    })

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $response = Invoke-EntraTokenHttpRequest -Uri $tokenUri -Method 'POST' -Body $body -UserAgent $UserAgent -Proxy $Proxy
        $payload = $null
        try {
            $payload = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        } catch {
            $payload = $null
        }
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300 -and $payload -and -not [string]::IsNullOrWhiteSpace([string]$payload.access_token)) {
            return $payload
        }
        $err = if ($payload) { [string]$payload.error } else { '' }
        if ($err -eq 'authorization_pending') {
            Start-Sleep -Seconds $interval
            continue
        }
        if ($err -eq 'slow_down') {
            $interval += 5
            Start-Sleep -Seconds $interval
            continue
        }
        $desc = if ($payload -and $payload.error_description) { [string]$payload.error_description } else { "HTTP $($response.StatusCode)" }
        throw "Device code token polling failed ($err): $desc"
    }
    throw "Timed out waiting for device code token after $TimeoutSeconds seconds."
}

function ConvertFrom-EntraJwtPayload {
    param([Parameter(Mandatory)][string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Length -lt 2) {
        return @{}
    }
    try {
        $bytes = ConvertFrom-Base64Url $parts[1]
        return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
    } catch {
        return @{}
    }
}

function Invoke-EntraPasskeyLoginForSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$BoundParameters,
        [AllowNull()][PSCustomObject]$CredentialFromPipeline,
        [switch]$QuietWarningsToStderr
    )
    $loginParams = @{}
    foreach ($name in @(
        'CredentialFromPipeline', 'KeyFilePath', 'UserPrincipalName', 'UserHandle',
        'CredentialIdentifier', 'PrivateKey', 'RelyingParty', 'UserAgent', 'Proxy',
        'KeyVaultName', 'KeyVaultKeyName', 'KeyVaultAccessToken', 'KeyVaultClientId',
        'KeyVaultClientSecret', 'KeyVaultTenantId'
    )) {
        if ($BoundParameters.ContainsKey($name)) {
            $loginParams[$name] = $BoundParameters[$name]
        }
    }
    if (-not $loginParams.ContainsKey('CredentialFromPipeline') -and $null -ne $CredentialFromPipeline) {
        $loginParams['CredentialFromPipeline'] = $CredentialFromPipeline
    }
    $loginParams['ConfirmApplication'] = $true
    $loginParams['PassThru'] = $true
    $loginParams['IncludeAuthenticationSession'] = $true
    if ($QuietWarningsToStderr) {
        [Console]::Error.WriteLine('WARNING: Research automation only: not a FIDO-certified authenticator. These flows do not perform authenticator user presence or verification; any UP/UV flags are synthetic. Tenant policy may reject them.')
        $loginParams['WarningAction'] = 'SilentlyContinue'
    }
    $login = Invoke-EntraPasskeyLogin @loginParams
    if (-not $login -or -not $login.Success -or -not $login.AuthenticationSession) {
        throw 'Passkey authentication did not produce an authenticated Entra session.'
    }
    return $login
}

function Clear-EntraPasskeyLoginSession {
    param([AllowNull()]$LoginResult)
    if ($null -eq $LoginResult) {
        return
    }
    if ($LoginResult.PSObject.Properties['AuthenticationSession']) {
        $LoginResult.AuthenticationSession = $null
    }
    if ($LoginResult.PSObject.Properties['AuthenticationCookieValue']) {
        $LoginResult.AuthenticationCookieValue = $null
    }
}

function Format-EntraPasskeyTokenResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$TokenPayload,
        [Parameter(Mandatory)]$LoginResult,
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$AuthFlow,
        [AllowNull()][string]$UserCode,
        [switch]$AsPlainText,
        [switch]$RawToken,
        [switch]$Json
    )
    $accessTokenText = [string]$TokenPayload.access_token
    $refreshTokenText = if ($TokenPayload.refresh_token) { [string]$TokenPayload.refresh_token } else { $null }
    $claims = ConvertFrom-EntraJwtPayload -Token $accessTokenText
    $expiresIn = if ($null -ne $TokenPayload.expires_in) { [int]$TokenPayload.expires_in } else { $null }
    $expiresOn = if ($null -ne $expiresIn) { [DateTimeOffset]::UtcNow.AddSeconds($expiresIn).ToString('o') } else { $null }
    $resolvedTenant = if ($claims.tid) { [string]$claims.tid } else { $Authority }
    $resolvedUpn = [string]($claims.upn ?? $claims.preferred_username ?? $LoginResult.UserPrincipalName)
    $resolvedScopes = if ($TokenPayload.scope) {
        [string]$TokenPayload.scope
    } elseif ($claims.scp) {
        [string]$claims.scp
    } else {
        $null
    }

    if ($RawToken) {
        return $accessTokenText
    }

    if ($Json) {
        $jsonObj = [ordered]@{
            success                  = $true
            authFlow                 = $AuthFlow
            tokenType                = [string]($TokenPayload.token_type ?? 'Bearer')
            tenantId                 = $resolvedTenant
            clientId                 = $ClientId
            userPrincipalName        = $resolvedUpn
            scopes                   = $resolvedScopes
            expiresIn                = $expiresIn
            expiresOn                = $expiresOn
            amr                      = @($claims.amr)
            signatureMethod          = $LoginResult.SignatureMethod
            keyVaultName             = $LoginResult.KeyVaultName
            userPresenceVerified     = [bool]$LoginResult.UserPresenceVerified
            userVerificationVerified = [bool]$LoginResult.UserVerificationVerified
        }
        if ($UserCode) { $jsonObj.userCode = $UserCode }
        if ($AsPlainText) {
            $jsonObj.accessToken = $accessTokenText
            if ($refreshTokenText) { $jsonObj.refreshToken = $refreshTokenText }
        }
        return ($jsonObj | ConvertTo-Json -Compress)
    }

    $accessOut = if ($AsPlainText) { $accessTokenText } else { ConvertTo-SecureString -String $accessTokenText -AsPlainText -Force }
    $refreshOut = if (-not $refreshTokenText) {
        $null
    } elseif ($AsPlainText) {
        $refreshTokenText
    } else {
        ConvertTo-SecureString -String $refreshTokenText -AsPlainText -Force
    }
    $result = [pscustomobject]@{
        Success                  = $true
        AuthFlow                 = $AuthFlow
        TokenType                = [string]($TokenPayload.token_type ?? 'Bearer')
        AccessToken              = $accessOut
        RefreshToken             = $refreshOut
        ExpiresIn                = $expiresIn
        ExpiresOn                = $expiresOn
        Scope                    = $resolvedScopes
        TenantId                 = $resolvedTenant
        ClientId                 = $ClientId
        UserPrincipalName        = $resolvedUpn
        Amr                      = @($claims.amr)
        AuthenticationMethod     = $LoginResult.AuthenticationMethod
        SignatureMethod          = $LoginResult.SignatureMethod
        KeyVaultName             = $LoginResult.KeyVaultName
        UserPresenceVerified     = $LoginResult.UserPresenceVerified
        UserVerificationVerified = $LoginResult.UserVerificationVerified
    }
    if ($UserCode) {
        $result | Add-Member -NotePropertyName UserCode -NotePropertyValue $UserCode
    }
    return $result
}
