# Bounded integration probe, not a general OIDC library. Trusts only fresh token
# responses obtained directly over authenticated TLS (OIDC Core 3.1.3.7 step 6).
# Never accepts a caller-supplied ID/access token or follows a token/API redirect.
function ConvertTo-LabProbeBase64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Read-LabProbeJson {
    param([string]$Text)
    $document = [System.Text.Json.JsonDocument]::Parse($Text)
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'Object required.' }
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $document.RootElement.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw 'Duplicate JSON property.' }
        }
        return ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 16 -ErrorAction Stop
    } finally { $document.Dispose() }
}

function Assert-LabProbeConfiguration {
    param([string]$TenantId, [string]$ClientId, [string]$ExpectedUpn)
    foreach ($value in @($TenantId, $ClientId)) {
        if ($value -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or [guid]$value -eq [guid]::Empty) {
            throw 'Explicit lowercase nonzero tenant and reviewed public-client IDs are required.'
        }
    }
    if ($ExpectedUpn.Length -gt 320 -or $ExpectedUpn -notmatch '\A[^\s@]+@[^\s@]+\z') { throw 'Expected lab UPN is required.' }
}

function New-LabProbeHttpHandler {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false; $handler.UseProxy = $false
    return $handler
}

function Send-LabProbeRequest {
    param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body)
    $target = [uri]$Uri
    if ($target.Scheme -cne 'https' -or $target.Port -ne 443 -or $target.UserInfo -or $target.Fragment -or
        $target.Host -cnotin @('login.microsoftonline.com', 'graph.microsoft.com')) { throw 'Untrusted probe destination.' }
    $handler = New-LabProbeHttpHandler
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $target)
    $response = $null; $stream = $null; $cancel = $null; $buffer = [IO.MemoryStream]::new()
    try {
        foreach ($key in $Headers.Keys) { $request.Headers.Add($key, [string]$Headers[$key]) }
        if ($Method -ceq 'POST') { $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/x-www-form-urlencoded') }
        $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($response.Content.Headers.ContentLength -gt 65536) { throw 'Response too large.' }
        $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(30))
        $stream = $response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
        $bytes = [byte[]]::new(4096)
        while ($true) {
            $count = $stream.ReadAsync($bytes, 0, $bytes.Length, $cancel.Token).GetAwaiter().GetResult()
            if ($count -eq 0) { break }
            if ($buffer.Length + $count -gt 65536) { throw 'Response too large.' }
            $buffer.Write($bytes, 0, $count)
        }
        $locations = @(); $values = $null
        if ($response.Headers.TryGetValues('Location', [ref]$values)) { $locations = @($values) }
        return @{ Status = [int]$response.StatusCode; Locations = $locations; ContentType = [string]$response.Content.Headers.ContentType.MediaType
            Body = [Text.UTF8Encoding]::new($false, $true).GetString($buffer.ToArray()) }
    } catch { throw 'Session probe transport failed; sensitive response suppressed.' }
    finally {
        if ($stream) { $stream.Dispose() }; if ($response) { $response.Dispose() }
        if ($cancel) { $cancel.Dispose() }; $buffer.Dispose(); $request.Dispose(); $client.Dispose()
    }
}

function ConvertTo-LabProbeForm {
    param([System.Collections.IDictionary]$Values)
    return (($Values.GetEnumerator() | ForEach-Object { [uri]::EscapeDataString([string]$_.Key) + '=' + [uri]::EscapeDataString([string]$_.Value) }) -join '&')
}

function Read-LabProbeResponse {
    param($Response)
    if ($Response.Status -ne 200 -or $Response.ContentType -cne 'application/json' -or @($Response.Locations).Count -ne 0) { throw 'Unexpected JSON response.' }
    return Read-LabProbeJson $Response.Body
}

function Invoke-LabSessionProbe {
    param([string]$Cookie, [string]$CookieName, [string]$TenantId, [string]$ClientId, [string]$ExpectedUpn)
    # The caller supplies only a cookie. All token material is acquired in this
    # function, in the current nonce/state/PKCE transaction, and never returned.
    # Phase identifies the entered operation, not proof a request reached a service.
    # Diagnostic labels are local literals only; never copy response/exception data.
    $phase = 'Configuration'; $failureCode = 'InvalidConfiguration'
    try {
        Assert-LabProbeConfiguration $TenantId $ClientId $ExpectedUpn
        $phase = 'Cookie'; $failureCode = 'UnexpectedFailure'
        if ($CookieName -cnotin @('ESTSAUTH','ESTSAUTHPERSISTENT') -or $Cookie.Length -gt 32768 -or
            $Cookie -cnotmatch '\A[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+\z') { $failureCode = 'InvalidCookie'; throw 'Invalid cookie.' }
        $authority = "https://login.microsoftonline.com/$TenantId"
        $redirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        $phase = 'DiscoveryRequest'
        $metadata = Send-LabProbeRequest "$authority/v2.0/.well-known/openid-configuration"
        $phase = 'DiscoveryResponse'; $failureCode = 'InvalidResponse'
        $metadata = Read-LabProbeResponse $metadata
        $phase = 'DiscoveryMetadata'; $failureCode = 'UnexpectedFailure'
        foreach ($pair in @(@('issuer', "$authority/v2.0"), @('authorization_endpoint', "$authority/oauth2/v2.0/authorize"),
            @('token_endpoint', "$authority/oauth2/v2.0/token"), @('userinfo_endpoint', 'https://graph.microsoft.com/oidc/userinfo'))) {
            if ($metadata[$pair[0]] -isnot [string] -or $metadata[$pair[0]] -cne $pair[1]) { $failureCode = 'InvalidMetadata'; throw 'Unexpected discovery metadata.' }
        }
        $phase = 'AuthorizationRequest'
        $state = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $nonce = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $verifier = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $challenge = ConvertTo-LabProbeBase64Url ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
        $query = ConvertTo-LabProbeForm ([ordered]@{ client_id=$ClientId; redirect_uri=$redirect; scope='openid profile'; response_type='code'; response_mode='query'
            prompt='none'; state=$state; nonce=$nonce; code_challenge=$challenge; code_challenge_method='S256' })
        $current = "$($metadata.authorization_endpoint)?$query"; $code = $null
        $response = Send-LabProbeRequest $current -Headers @{ Cookie = "$CookieName=$Cookie" }
        $phase = 'AuthorizationResponse'
        if ($response.Status -notin @(302,303) -or @($response.Locations).Count -ne 1) { $failureCode = 'InvalidAuthorizationResponse'; throw 'Silent session reuse failed; no interaction or consent is attempted.' }
        $phase = 'Callback'; $failureCode = 'InvalidCallback'
        $next = [uri]::new([uri]$current, [string]$response.Locations[0])
        if ($next.Scheme -cne 'https' -or $next.Host -cne 'login.microsoftonline.com' -or $next.Port -ne 443 -or $next.UserInfo -or $next.Fragment -or
            $next.GetLeftPart([UriPartial]::Path) -cne $redirect) { throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $fields = [Web.HttpUtility]::ParseQueryString($next.Query)
        foreach ($name in $fields.AllKeys) { if (-not $name -or @($fields.GetValues($name)).Count -ne 1) { throw 'Ambiguous callback.' } }
        if ($fields['error'] -or $fields['state'] -cne $state -or [string]::IsNullOrWhiteSpace($fields['code']) -or $fields['code'].Length -gt 16384) { throw 'Callback binding failed.' }
        $failureCode = 'UnexpectedFailure'
        $code = $fields['code']
        $phase = 'TokenRequest'
        $body = ConvertTo-LabProbeForm @{ grant_type='authorization_code'; client_id=$ClientId; redirect_uri=$redirect; code=$code; code_verifier=$verifier; scope='openid profile' }
        $tokens = Send-LabProbeRequest $metadata.token_endpoint -Method POST -Body $body
        $phase = 'TokenResponse'; $failureCode = 'InvalidResponse'
        $tokens = Read-LabProbeResponse $tokens
        $failureCode = 'UnexpectedFailure'
        if ($tokens.token_type -isnot [string] -or $tokens.token_type -ine 'Bearer' -or $tokens.access_token -isnot [string] -or
            [string]::IsNullOrWhiteSpace($tokens.access_token) -or $tokens.access_token -match '[\r\n]' -or $tokens.id_token -isnot [string] -or $tokens.refresh_token) { $failureCode = 'InvalidTokenResponse'; throw 'Unexpected token response.' }
        if ($tokens.Contains('scope')) {
            if ($tokens.scope -isnot [string] -or $tokens.scope -cnotmatch '\A(?:openid|profile)(?: (?:openid|profile))*\z') { $failureCode = 'InvalidTokenResponse'; throw 'Unexpected granted scopes.' }
        }
        $phase = 'TokenEncoding'; $failureCode = 'InvalidTokenEncoding'
        $parts = $tokens.id_token.Split('.')
        if ($parts.Count -ne 3) { throw 'Malformed ID token.' }
        $jsonParts = @()
        foreach ($part in $parts[0..1]) {
            if ($part -cnotmatch '\A[A-Za-z0-9_-]+\z' -or $part.Length % 4 -eq 1) { throw 'Malformed token encoding.' }
            $encoded = $part.Replace('-','+').Replace('_','/') + ('=' * ((4 - $part.Length % 4) % 4))
            $jsonParts += Read-LabProbeJson ([Text.UTF8Encoding]::new($false, $true).GetString([Convert]::FromBase64String($encoded)))
        }
        $header = $jsonParts[0]; $claims = $jsonParts[1]
        if ($header.alg -isnot [string] -or $header.alg -cne 'RS256' -or $header.Contains('crit') -or $parts[2] -cnotmatch '\A[A-Za-z0-9_-]+\z') { throw 'Unexpected ID token format.' }
        $phase = 'TokenBinding'; $failureCode = 'UnexpectedFailure'
        foreach ($pair in @(@('iss', $metadata.issuer), @('aud', $ClientId), @('tid', $TenantId), @('nonce', $nonce))) {
            if ($claims[$pair[0]] -isnot [string] -or $claims[$pair[0]] -cne $pair[1]) { $failureCode = 'InvalidTokenBinding'; throw 'ID token binding failed.' }
        }
        if ($claims.Contains('azp') -and ($claims.azp -isnot [string] -or $claims.azp -cne $ClientId)) { $failureCode = 'InvalidTokenBinding'; throw 'Unexpected authorized party.' }
        if ($claims.oid -isnot [string] -or $claims.oid -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or [guid]$claims.oid -eq [guid]::Empty) { $failureCode = 'InvalidTokenBinding'; throw 'Invalid object identity.' }
        if ($claims.preferred_username -isnot [string] -or $claims.preferred_username -ine $ExpectedUpn -or
            $claims.sub -isnot [string] -or [string]::IsNullOrWhiteSpace($claims.sub)) { $failureCode = 'InvalidTokenBinding'; throw 'User binding failed.' }
        $phase = 'TokenTimes'
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        foreach ($name in @('iat','exp')) { if ($claims[$name] -isnot [long] -and $claims[$name] -isnot [int]) { $failureCode = 'InvalidTokenTimes'; throw 'Invalid token time.' } }
        if ($claims.exp -le $now -or $claims.iat -gt $now + 60 -or $claims.iat -lt $now - 300 -or $claims.exp -le $claims.iat) { $failureCode = 'InvalidTokenTimes'; throw 'Token is not fresh.' }
        if ($claims.Contains('nbf') -and (($claims.nbf -isnot [long] -and $claims.nbf -isnot [int]) -or $claims.nbf -gt $now + 60)) { $failureCode = 'InvalidTokenTimes'; throw 'Token not yet valid.' }
        $phase = 'UserInfoRequest'
        $user = Send-LabProbeRequest $metadata.userinfo_endpoint -Headers @{ Authorization = "Bearer $($tokens.access_token)" }
        $phase = 'UserInfoResponse'; $failureCode = 'InvalidResponse'
        $user = Read-LabProbeResponse $user
        $phase = 'UserInfoSubject'; $failureCode = 'UnexpectedFailure'
        if ($user.sub -isnot [string] -or $user.sub -cne $claims.sub) { $failureCode = 'InvalidUserInfoSubject'; throw 'UserInfo subject mismatch.' }
        return [ordered]@{ ServerBackedSessionReuse = $true; ExpectedTenantAndCurrentName = $true; UserInfoSubjectMatched = $true; TamperProofAgainstCandidate = $false }
    } catch {
        # Validate at the public emission boundary. Unknown labels never reach output.
        if ($phase -isnot [string] -or $phase -cnotin @('Configuration', 'Cookie', 'DiscoveryRequest', 'DiscoveryResponse', 'DiscoveryMetadata',
            'AuthorizationRequest', 'AuthorizationResponse', 'Callback', 'TokenRequest', 'TokenResponse',
            'TokenEncoding', 'TokenBinding', 'TokenTimes', 'UserInfoRequest', 'UserInfoResponse', 'UserInfoSubject')) { $phase = 'Unknown' }
        if ($failureCode -isnot [string] -or $failureCode -cnotin @('InvalidConfiguration', 'InvalidCookie', 'InvalidResponse', 'InvalidMetadata',
            'InvalidAuthorizationResponse', 'InvalidCallback', 'InvalidTokenResponse', 'InvalidTokenEncoding',
            'InvalidTokenBinding', 'InvalidTokenTimes', 'InvalidUserInfoSubject', 'UnexpectedFailure')) { $failureCode = 'UnexpectedFailure' }
        throw "Server-backed session probe failed; no live acceptance. Sensitive details suppressed. Phase=$phase; Code=$failureCode."
    }
    finally { $Cookie = $null; $code = $null; $verifier = $null; $body = $null; $tokens = $null; $claims = $null; $user = $null }
}
