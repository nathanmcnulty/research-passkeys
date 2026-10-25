# Bounded integration probe, not a general OIDC library. Trusts only fresh token
# responses obtained directly over authenticated TLS (OIDC Core 3.1.3.7 step 6).
# Never accepts a caller-supplied ID/access token or follows a token/API redirect.
function ConvertTo-LabProbeBase64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Read-LabProbeJson {
    param([string]$Text, [hashtable]$Diagnostic = @{}, [string]$Context = 'Response')
    $category = $Diagnostic.Code
    # Context comes only from fixed local call sites; no JSON property is a label.
    $ids = switch -CaseSensitive ($Context) {
        'Response' { @('ResponseJsonParse', 'ResponseJsonRootObject', 'ResponseJsonPropertySetConstruction', 'ResponseJsonPropertiesRead', 'ResponseJsonPropertyUnique', 'ResponseJsonConversion', 'ResponseJsonDispose') }
        'Header' { @('HeaderJsonParse', 'HeaderJsonRootObject', 'HeaderJsonPropertySetConstruction', 'HeaderJsonPropertiesRead', 'HeaderJsonPropertyUnique', 'HeaderJsonConversion', 'HeaderJsonDispose') }
        'Claims' { @('ClaimsJsonParse', 'ClaimsJsonRootObject', 'ClaimsJsonPropertySetConstruction', 'ClaimsJsonPropertiesRead', 'ClaimsJsonPropertyUnique', 'ClaimsJsonConversion', 'ClaimsJsonDispose') }
        default { @('UnexpectedFailure', 'UnexpectedFailure', 'UnexpectedFailure', 'UnexpectedFailure', 'UnexpectedFailure', 'UnexpectedFailure', 'UnexpectedFailure') }
    }
    $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[0]
    $document = [System.Text.Json.JsonDocument]::Parse($Text)
    $failed = $false
    try {
        $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[1]; throw 'Object required.' }
        $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[2]
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[3]
        foreach ($property in $document.RootElement.EnumerateObject()) {
            $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
            if (-not $names.Add($property.Name)) { $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[4]; throw 'Duplicate JSON property.' }
        }
        $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[5]
        return ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 16 -ErrorAction Stop
    } catch { $failed = $true; throw }
    finally {
        if (-not $failed) { $Diagnostic.Code = $category; $Diagnostic.Predicate = $ids[6] }
        $document.Dispose()
        if (-not $failed) { $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure' }
    }
}

function Assert-LabProbeConfiguration {
    param([string]$TenantId, [string]$ClientId, [string]$ExpectedUpn, [hashtable]$Diagnostic = @{})
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    foreach ($pair in @(@($TenantId, 'TenantFormat', 'TenantNonzero'), @($ClientId, 'ClientFormat', 'ClientNonzero'))) {
        $value = $pair[0]
        $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
        if ($value -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z') { $Diagnostic.Code = 'InvalidConfiguration'; $Diagnostic.Predicate = $pair[1]; throw 'Explicit lowercase nonzero tenant and reviewed public-client IDs are required.' }
        $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
        if ([guid]$value -eq [guid]::Empty) { $Diagnostic.Code = 'InvalidConfiguration'; $Diagnostic.Predicate = $pair[2]; throw 'Explicit lowercase nonzero tenant and reviewed public-client IDs are required.' }
    }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($ExpectedUpn.Length -gt 320) { $Diagnostic.Code = 'InvalidConfiguration'; $Diagnostic.Predicate = 'UpnLength'; throw 'Expected lab UPN is required.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($ExpectedUpn -notmatch '\A[^\s@]+@[^\s@]+\z') { $Diagnostic.Code = 'InvalidConfiguration'; $Diagnostic.Predicate = 'UpnFormat'; throw 'Expected lab UPN is required.' }
}

function New-LabProbeHttpHandler {
    param([hashtable]$Diagnostic = @{})
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportHandlerConstruction'
    $handler = [Net.Http.HttpClientHandler]::new()
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportRedirectPolicy'; $handler.AllowAutoRedirect = $false
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportCookiePolicy'; $handler.UseCookies = $false
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportCredentialPolicy'; $handler.UseDefaultCredentials = $false
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportProxyPolicy'; $handler.UseProxy = $false
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    return $handler
}

function Send-LabProbeRequest {
    param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body, [hashtable]$Diagnostic = @{})
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportUriConstruction'
    $target = [uri]$Uri
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($target.Scheme -cne 'https') { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportScheme'; throw 'Untrusted probe destination.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($target.Port -ne 443) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportPort'; throw 'Untrusted probe destination.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($target.UserInfo) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportUserInfo'; throw 'Untrusted probe destination.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($target.Fragment) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportFragment'; throw 'Untrusted probe destination.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($target.Host -cnotin @('login.microsoftonline.com', 'graph.microsoft.com')) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportHost'; throw 'Untrusted probe destination.' }
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportHandlerConstruction'
    $handler = New-LabProbeHttpHandler -Diagnostic $Diagnostic
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportClientConstruction'
    $client = [Net.Http.HttpClient]::new($handler)
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportTimeoutConfiguration'
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportMethodConstruction'
    $httpMethod = [Net.Http.HttpMethod]::new($Method)
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportRequestConstruction'
    $request = [Net.Http.HttpRequestMessage]::new($httpMethod, $target)
    $response = $null; $stream = $null; $cancel = $null
    $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportBufferConstruction'
    $buffer = [IO.MemoryStream]::new()
    $failed = $false
    try {
        foreach ($key in $Headers.Keys) {
            $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportHeaderConstruction'
            $request.Headers.Add($key, [string]$Headers[$key])
            $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
        }
        if ($Method -ceq 'POST') {
            $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportBodyConstruction'
            $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/x-www-form-urlencoded')
        }
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportSend'
        $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
        if ($response.Content.Headers.ContentLength -gt 65536) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportAdvertisedLimit'; throw 'Response too large.' }
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportDeadlineConstruction'
        $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(30))
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportStreamOpen'
        $stream = $response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportReadBufferConstruction'
        $bytes = [byte[]]::new(4096)
        while ($true) {
            $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportRead'
            $count = $stream.ReadAsync($bytes, 0, $bytes.Length, $cancel.Token).GetAwaiter().GetResult()
            if ($count -eq 0) { break }
            $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
            if ($buffer.Length + $count -gt 65536) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportStreamedLimit'; throw 'Response too large.' }
            $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportBufferWrite'
            $buffer.Write($bytes, 0, $count)
        }
        $locations = @(); $values = $null
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportLocationRead'
        if ($response.Headers.TryGetValues('Location', [ref]$values)) { $locations = @($values) }
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportResponseProjection'
        $result = @{ Status = [int]$response.StatusCode; Locations = $locations; ContentType = [string]$response.Content.Headers.ContentType.MediaType }
        $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportUtf8Decode'
        $result.Body = [Text.UTF8Encoding]::new($false, $true).GetString($buffer.ToArray())
        return $result
    } catch { $failed = $true; throw 'Session probe transport failed; sensitive response suppressed.' }
    finally {
        # Preserve the first failure label even if disposal replaces its exception.
        # Disposal order and stop-on-throw behavior are deliberately unchanged.
        if ($stream) {
            if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportStreamDispose' }
            $stream.Dispose()
        }
        if ($response) {
            if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportResponseDispose' }
            $response.Dispose()
        }
        if ($cancel) {
            if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportDeadlineDispose' }
            $cancel.Dispose()
        }
        if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportBufferDispose' }
        $buffer.Dispose()
        if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportRequestDispose' }
        $request.Dispose()
        if (-not $failed) { $Diagnostic.Code = 'TransportFailure'; $Diagnostic.Predicate = 'TransportClientDispose' }
        $client.Dispose()
        if (-not $failed) { $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure' }
    }
}

function ConvertTo-LabProbeForm {
    param([System.Collections.IDictionary]$Values)
    return (($Values.GetEnumerator() | ForEach-Object { [uri]::EscapeDataString([string]$_.Key) + '=' + [uri]::EscapeDataString([string]$_.Value) }) -join '&')
}

function Read-LabProbeResponse {
    param($Response, [hashtable]$Diagnostic = @{})
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($Response.Status -ne 200) { $Diagnostic.Code = 'InvalidResponse'; $Diagnostic.Predicate = 'ResponseStatus'; throw 'Unexpected JSON response.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if ($Response.ContentType -cne 'application/json') { $Diagnostic.Code = 'InvalidResponse'; $Diagnostic.Predicate = 'ResponseMediaType'; throw 'Unexpected JSON response.' }
    $Diagnostic.Code = 'UnexpectedFailure'; $Diagnostic.Predicate = 'UnexpectedFailure'
    if (@($Response.Locations).Count -ne 0) { $Diagnostic.Code = 'InvalidResponse'; $Diagnostic.Predicate = 'ResponseLocations'; throw 'Unexpected JSON response.' }
    $Diagnostic.Code = 'InvalidResponse'
    return Read-LabProbeJson $Response.Body -Diagnostic $Diagnostic -Context 'Response'
}

function Invoke-LabSessionProbe {
    param([string]$Cookie, [string]$CookieName, [string]$TenantId, [string]$ClientId, [string]$ExpectedUpn)
    # These IDs identify the first rejected check or entered failing operation,
    # not response values, a terminal exception, or proof a request reached a service.
    $phase = 'Configuration'
    $diagnostic = @{ Code = 'UnexpectedFailure'; Predicate = 'ConfigurationValidation' }
    try {
        Assert-LabProbeConfiguration $TenantId $ClientId $ExpectedUpn -Diagnostic $diagnostic
        $phase = 'Cookie'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($CookieName -cnotin @('ESTSAUTH','ESTSAUTHPERSISTENT')) { $diagnostic.Code = 'InvalidCookie'; $diagnostic.Predicate = 'CookieName'; throw 'Invalid cookie.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($Cookie.Length -gt 32768) { $diagnostic.Code = 'InvalidCookie'; $diagnostic.Predicate = 'CookieLength'; throw 'Invalid cookie.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($Cookie -cnotmatch '\A[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+\z') { $diagnostic.Code = 'InvalidCookie'; $diagnostic.Predicate = 'CookieAlphabet'; throw 'Invalid cookie.' }
        $authority = "https://login.microsoftonline.com/$TenantId"
        $redirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        $phase = 'DiscoveryRequest'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'RequestInvocation'
        $metadata = Send-LabProbeRequest "$authority/v2.0/.well-known/openid-configuration" -Diagnostic $diagnostic
        $phase = 'DiscoveryResponse'
        $metadata = Read-LabProbeResponse $metadata -Diagnostic $diagnostic
        $phase = 'DiscoveryMetadata'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        foreach ($pair in @(@('issuer', "$authority/v2.0", 'IssuerMetadataString', 'IssuerMetadataMatch'),
            @('authorization_endpoint', "$authority/oauth2/v2.0/authorize", 'AuthorizationMetadataString', 'AuthorizationMetadataMatch'),
            @('token_endpoint', "$authority/oauth2/v2.0/token", 'TokenMetadataString', 'TokenMetadataMatch'),
            @('userinfo_endpoint', 'https://graph.microsoft.com/oidc/userinfo', 'UserInfoMetadataString', 'UserInfoMetadataMatch'))) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($metadata[$pair[0]] -isnot [string]) { $diagnostic.Code = 'InvalidMetadata'; $diagnostic.Predicate = $pair[2]; throw 'Unexpected discovery metadata.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($metadata[$pair[0]] -cne $pair[1]) { $diagnostic.Code = 'InvalidMetadata'; $diagnostic.Predicate = $pair[3]; throw 'Unexpected discovery metadata.' }
        }
        $phase = 'AuthorizationRequest'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'StateCreation'
        $state = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'NonceCreation'
        $nonce = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'VerifierCreation'
        $verifier = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'ChallengeCreation'
        $challenge = ConvertTo-LabProbeBase64Url ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'AuthorizationFormCreation'
        $query = ConvertTo-LabProbeForm ([ordered]@{ client_id=$ClientId; redirect_uri=$redirect; scope='openid profile'; response_type='code'; response_mode='query'
            prompt='none'; state=$state; nonce=$nonce; code_challenge=$challenge; code_challenge_method='S256' })
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'AuthorizationUriConstruction'
        $current = "$($metadata.authorization_endpoint)?$query"; $code = $null
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'RequestInvocation'
        $response = Send-LabProbeRequest $current -Headers @{ Cookie = "$CookieName=$Cookie" } -Diagnostic $diagnostic
        $phase = 'AuthorizationResponse'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($response.Status -notin @(302,303)) { $diagnostic.Code = 'InvalidAuthorizationResponse'; $diagnostic.Predicate = 'AuthorizationStatus'; throw 'Silent session reuse failed; no interaction or consent is attempted.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if (@($response.Locations).Count -ne 1) { $diagnostic.Code = 'InvalidAuthorizationResponse'; $diagnostic.Predicate = 'AuthorizationLocationCount'; throw 'Silent session reuse failed; no interaction or consent is attempted.' }
        $phase = 'Callback'; $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackUriConstruction'
        $next = [uri]::new([uri]$current, [string]$response.Locations[0])
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.Scheme -cne 'https') { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackScheme'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.Host -cne 'login.microsoftonline.com') { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackHost'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.Port -ne 443) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackPort'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.UserInfo) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackUserInfo'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.Fragment) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackFragment'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($next.GetLeftPart([UriPartial]::Path) -cne $redirect) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackPath'; throw 'Unexpected authorization redirect; cookie is never forwarded.' }
        $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackQueryParsing'
        $fields = [Web.HttpUtility]::ParseQueryString($next.Query)
        foreach ($name in $fields.AllKeys) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if (-not $name) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackKeyName'; throw 'Ambiguous callback.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if (@($fields.GetValues($name)).Count -ne 1) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackKeyMultiplicity'; throw 'Ambiguous callback.' }
        }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($fields['error']) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackErrorAbsent'; throw 'Callback binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($fields['state'] -cne $state) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackStateMatch'; throw 'Callback binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ([string]::IsNullOrWhiteSpace($fields['code'])) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackCodePresent'; throw 'Callback binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($fields['code'].Length -gt 16384) { $diagnostic.Code = 'InvalidCallback'; $diagnostic.Predicate = 'CallbackCodeLength'; throw 'Callback binding failed.' }
        $code = $fields['code']
        $phase = 'TokenRequest'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'TokenFormCreation'
        $body = ConvertTo-LabProbeForm @{ grant_type='authorization_code'; client_id=$ClientId; redirect_uri=$redirect; code=$code; code_verifier=$verifier; scope='openid profile' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'RequestInvocation'
        $tokens = Send-LabProbeRequest $metadata.token_endpoint -Method POST -Body $body -Diagnostic $diagnostic
        $phase = 'TokenResponse'
        $tokens = Read-LabProbeResponse $tokens -Diagnostic $diagnostic
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.token_type -isnot [string]) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'TokenTypeString'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.token_type -ine 'Bearer') { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'TokenTypeBearer'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.access_token -isnot [string]) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'AccessTokenString'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ([string]::IsNullOrWhiteSpace($tokens.access_token)) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'AccessTokenNonblank'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.access_token -match '[\r\n]') { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'AccessTokenNoNewline'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.id_token -isnot [string]) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'IdTokenString'; throw 'Unexpected token response.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($tokens.refresh_token) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'RefreshTokenFalsey'; throw 'Unexpected token response.' }
        if ($tokens.Contains('scope')) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($tokens.scope -isnot [string]) { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'ScopeString'; throw 'Unexpected granted scopes.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($tokens.scope -cnotmatch '\A(?:openid|profile)(?: (?:openid|profile))*\z') { $diagnostic.Code = 'InvalidTokenResponse'; $diagnostic.Predicate = 'ScopeAllowedGrammar'; throw 'Unexpected granted scopes.' }
        }
        $phase = 'TokenEncoding'; $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'TokenSplit'
        $parts = $tokens.id_token.Split('.')
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($parts.Count -ne 3) { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'TokenPartCount'; throw 'Malformed ID token.' }
        $jsonParts = @()
        $partIndex = 0
        foreach ($part in $parts[0..1]) {
            $partIds = if ($partIndex -eq 0) { @('HeaderAlphabet', 'HeaderLength', 'HeaderBase64Decode', 'HeaderUtf8Decode', 'Header', 'HeaderUtf8Construction') }
                else { @('ClaimsAlphabet', 'ClaimsLength', 'ClaimsBase64Decode', 'ClaimsUtf8Decode', 'Claims', 'ClaimsUtf8Construction') }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($part -cnotmatch '\A[A-Za-z0-9_-]+\z') { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = $partIds[0]; throw 'Malformed token encoding.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($part.Length % 4 -eq 1) { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = $partIds[1]; throw 'Malformed token encoding.' }
            $encoded = $part.Replace('-','+').Replace('_','/') + ('=' * ((4 - $part.Length % 4) % 4))
            $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = $partIds[5]
            $decoder = [Text.UTF8Encoding]::new($false, $true)
            $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = $partIds[2]
            $encoded = [Convert]::FromBase64String($encoded)
            $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = $partIds[3]
            $encoded = $decoder.GetString($encoded)
            $diagnostic.Code = 'InvalidTokenEncoding'
            $jsonParts += Read-LabProbeJson $encoded -Diagnostic $diagnostic -Context $partIds[4]
            $partIndex++
        }
        $header = $jsonParts[0]; $claims = $jsonParts[1]
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($header.alg -isnot [string]) { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'HeaderAlgorithmString'; throw 'Unexpected ID token format.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($header.alg -cne 'RS256') { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'HeaderAlgorithmMatch'; throw 'Unexpected ID token format.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($header.Contains('crit')) { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'HeaderCriticalAbsent'; throw 'Unexpected ID token format.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($parts[2] -cnotmatch '\A[A-Za-z0-9_-]+\z') { $diagnostic.Code = 'InvalidTokenEncoding'; $diagnostic.Predicate = 'SignatureAlphabet'; throw 'Unexpected ID token format.' }
        $phase = 'TokenBinding'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        foreach ($pair in @(@('iss', $metadata.issuer, 'IssuerClaimString', 'IssuerClaimMatch'),
            @('aud', $ClientId, 'AudienceClaimString', 'AudienceClaimMatch'),
            @('tid', $TenantId, 'TenantClaimString', 'TenantClaimMatch'),
            @('nonce', $nonce, 'NonceClaimString', 'NonceClaimMatch'))) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims[$pair[0]] -isnot [string]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = $pair[2]; throw 'ID token binding failed.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims[$pair[0]] -cne $pair[1]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = $pair[3]; throw 'ID token binding failed.' }
        }
        if ($claims.Contains('azp')) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims.azp -isnot [string]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'AuthorizedPartyString'; throw 'Unexpected authorized party.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims.azp -cne $ClientId) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'AuthorizedPartyMatch'; throw 'Unexpected authorized party.' }
        }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.oid -isnot [string]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'ObjectIdString'; throw 'Invalid object identity.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.oid -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z') { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'ObjectIdFormat'; throw 'Invalid object identity.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ([guid]$claims.oid -eq [guid]::Empty) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'ObjectIdNonzero'; throw 'Invalid object identity.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.preferred_username -isnot [string]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'UsernameString'; throw 'User binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.preferred_username -ine $ExpectedUpn) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'UsernameMatch'; throw 'User binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.sub -isnot [string]) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'SubjectString'; throw 'User binding failed.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ([string]::IsNullOrWhiteSpace($claims.sub)) { $diagnostic.Code = 'InvalidTokenBinding'; $diagnostic.Predicate = 'SubjectNonblank'; throw 'User binding failed.' }
        $phase = 'TokenTimes'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'ClockRead'
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        foreach ($pair in @(@('iat', 'IssuedAtInteger'), @('exp', 'ExpiryInteger'))) {
            $name = $pair[0]; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims[$name] -isnot [long] -and $claims[$name] -isnot [int]) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = $pair[1]; throw 'Invalid token time.' }
        }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.exp -le $now) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'ExpiryFuture'; throw 'Token is not fresh.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.iat -gt $now + 60) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'IssuedAtNotFuture'; throw 'Token is not fresh.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.iat -lt $now - 300) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'IssuedAtRecent'; throw 'Token is not fresh.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($claims.exp -le $claims.iat) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'ExpiryAfterIssuedAt'; throw 'Token is not fresh.' }
        if ($claims.Contains('nbf')) {
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims.nbf -isnot [long] -and $claims.nbf -isnot [int]) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'NotBeforeInteger'; throw 'Token not yet valid.' }
            $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
            if ($claims.nbf -gt $now + 60) { $diagnostic.Code = 'InvalidTokenTimes'; $diagnostic.Predicate = 'NotBeforeNotFuture'; throw 'Token not yet valid.' }
        }
        $phase = 'UserInfoRequest'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'RequestInvocation'
        $user = Send-LabProbeRequest $metadata.userinfo_endpoint -Headers @{ Authorization = "Bearer $($tokens.access_token)" } -Diagnostic $diagnostic
        $phase = 'UserInfoResponse'
        $user = Read-LabProbeResponse $user -Diagnostic $diagnostic
        $phase = 'UserInfoSubject'; $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($user.sub -isnot [string]) { $diagnostic.Code = 'InvalidUserInfoSubject'; $diagnostic.Predicate = 'UserInfoSubjectString'; throw 'UserInfo subject mismatch.' }
        $diagnostic.Code = 'UnexpectedFailure'; $diagnostic.Predicate = 'UnexpectedFailure'
        if ($user.sub -cne $claims.sub) { $diagnostic.Code = 'InvalidUserInfoSubject'; $diagnostic.Predicate = 'UserInfoSubjectMatch'; throw 'UserInfo subject mismatch.' }
        return [ordered]@{ ServerBackedSessionReuse = $true; ExpectedTenantAndCurrentName = $true; UserInfoSubjectMatched = $true; TamperProofAgainstCandidate = $false }
    } catch {
        # Only locally assigned scalar-string tuples may cross the public boundary.
        $failureCode = $null; $predicate = $null
        if ($diagnostic -is [hashtable]) { $failureCode = $diagnostic.Code; $predicate = $diagnostic.Predicate }
        $allowed = Get-LabProbeDiagnosticAllowlist
        if ($phase -isnot [string] -or $failureCode -isnot [string] -or $predicate -isnot [string] -or
            "$phase/$failureCode" -cnotin @($allowed.Keys) -or $predicate -cnotin $allowed["$phase/$failureCode"]) {
            $phase = 'Unknown'; $failureCode = 'UnexpectedFailure'; $predicate = 'UnexpectedFailure'
        }
        throw "Server-backed session probe failed; no live acceptance. Sensitive details suppressed. Phase=$phase; Code=$failureCode; Predicate=$predicate."
    }
    finally { $Cookie = $null; $code = $null; $verifier = $null; $body = $null; $tokens = $null; $claims = $null; $user = $null }
}

function Get-LabProbeDiagnosticAllowlist {
    # Static vocabulary only. No response, exception, claim value or type name is reflected.
    return @{
        'Configuration/InvalidConfiguration' = @(
            'TenantFormat', 'TenantNonzero', 'ClientFormat', 'ClientNonzero',
            'UpnLength', 'UpnFormat'
        )
        'Configuration/UnexpectedFailure' = @(
            'ConfigurationValidation', 'UnexpectedFailure'
        )
        'Cookie/InvalidCookie' = @(
            'CookieName', 'CookieLength', 'CookieAlphabet'
        )
        'DiscoveryResponse/InvalidResponse' = @(
            'ResponseStatus', 'ResponseMediaType', 'ResponseLocations', 'ResponseJsonParse',
            'ResponseJsonRootObject', 'ResponseJsonPropertySetConstruction', 'ResponseJsonPropertiesRead', 'ResponseJsonPropertyUnique',
            'ResponseJsonConversion', 'ResponseJsonDispose'
        )
        'DiscoveryMetadata/InvalidMetadata' = @(
            'IssuerMetadataString', 'IssuerMetadataMatch', 'AuthorizationMetadataString', 'AuthorizationMetadataMatch',
            'TokenMetadataString', 'TokenMetadataMatch', 'UserInfoMetadataString', 'UserInfoMetadataMatch'
        )
        'AuthorizationResponse/InvalidAuthorizationResponse' = @(
            'AuthorizationStatus', 'AuthorizationLocationCount'
        )
        'Callback/InvalidCallback' = @(
            'CallbackUriConstruction', 'CallbackScheme', 'CallbackHost', 'CallbackPort',
            'CallbackUserInfo', 'CallbackFragment', 'CallbackPath', 'CallbackQueryParsing',
            'CallbackKeyName', 'CallbackKeyMultiplicity', 'CallbackErrorAbsent', 'CallbackStateMatch',
            'CallbackCodePresent', 'CallbackCodeLength'
        )
        'TokenResponse/InvalidTokenResponse' = @(
            'TokenTypeString', 'TokenTypeBearer', 'AccessTokenString', 'AccessTokenNonblank',
            'AccessTokenNoNewline', 'IdTokenString', 'RefreshTokenFalsey', 'ScopeString',
            'ScopeAllowedGrammar'
        )
        'TokenEncoding/InvalidTokenEncoding' = @(
            'HeaderUtf8Construction', 'ClaimsUtf8Construction',
            'TokenSplit', 'TokenPartCount', 'HeaderAlphabet', 'HeaderLength',
            'HeaderBase64Decode', 'HeaderUtf8Decode', 'HeaderJsonParse', 'HeaderJsonRootObject',
            'HeaderJsonPropertySetConstruction', 'HeaderJsonPropertiesRead', 'HeaderJsonPropertyUnique', 'HeaderJsonConversion',
            'HeaderJsonDispose', 'ClaimsAlphabet', 'ClaimsLength', 'ClaimsBase64Decode',
            'ClaimsUtf8Decode', 'ClaimsJsonParse', 'ClaimsJsonRootObject', 'ClaimsJsonPropertySetConstruction',
            'ClaimsJsonPropertiesRead', 'ClaimsJsonPropertyUnique', 'ClaimsJsonConversion', 'ClaimsJsonDispose',
            'HeaderAlgorithmString', 'HeaderAlgorithmMatch', 'HeaderCriticalAbsent', 'SignatureAlphabet'
        )
        'TokenBinding/InvalidTokenBinding' = @(
            'IssuerClaimString', 'IssuerClaimMatch', 'AudienceClaimString', 'AudienceClaimMatch',
            'TenantClaimString', 'TenantClaimMatch', 'NonceClaimString', 'NonceClaimMatch',
            'AuthorizedPartyString', 'AuthorizedPartyMatch', 'ObjectIdString', 'ObjectIdFormat',
            'ObjectIdNonzero', 'UsernameString', 'UsernameMatch', 'SubjectString',
            'SubjectNonblank'
        )
        'TokenTimes/InvalidTokenTimes' = @(
            'IssuedAtInteger', 'ExpiryInteger', 'ExpiryFuture', 'IssuedAtNotFuture',
            'IssuedAtRecent', 'ExpiryAfterIssuedAt', 'NotBeforeInteger', 'NotBeforeNotFuture'
        )
        'UserInfoSubject/InvalidUserInfoSubject' = @(
            'UserInfoSubjectString', 'UserInfoSubjectMatch'
        )
        'DiscoveryRequest/UnexpectedFailure' = @(
            'RequestInvocation', 'UnexpectedFailure'
        )
        'AuthorizationRequest/UnexpectedFailure' = @(
            'StateCreation', 'NonceCreation', 'VerifierCreation', 'ChallengeCreation',
            'AuthorizationFormCreation', 'AuthorizationUriConstruction', 'RequestInvocation', 'UnexpectedFailure'
        )
        'TokenRequest/UnexpectedFailure' = @(
            'TokenFormCreation', 'RequestInvocation', 'UnexpectedFailure'
        )
        'UserInfoRequest/UnexpectedFailure' = @(
            'RequestInvocation', 'UnexpectedFailure'
        )
        'TokenTimes/UnexpectedFailure' = @(
            'ClockRead', 'UnexpectedFailure'
        )
        'AuthorizationResponse/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'Callback/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'Cookie/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'DiscoveryMetadata/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'DiscoveryResponse/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'TokenBinding/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'TokenEncoding/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'TokenResponse/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'UserInfoResponse/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'UserInfoSubject/UnexpectedFailure' = @(
            'UnexpectedFailure'
        )
        'TokenResponse/InvalidResponse' = @(
            'ResponseStatus', 'ResponseMediaType', 'ResponseLocations', 'ResponseJsonParse',
            'ResponseJsonRootObject', 'ResponseJsonPropertySetConstruction', 'ResponseJsonPropertiesRead', 'ResponseJsonPropertyUnique',
            'ResponseJsonConversion', 'ResponseJsonDispose'
        )
        'UserInfoResponse/InvalidResponse' = @(
            'ResponseStatus', 'ResponseMediaType', 'ResponseLocations', 'ResponseJsonParse',
            'ResponseJsonRootObject', 'ResponseJsonPropertySetConstruction', 'ResponseJsonPropertiesRead', 'ResponseJsonPropertyUnique',
            'ResponseJsonConversion', 'ResponseJsonDispose'
        )
        'DiscoveryRequest/TransportFailure' = @(
            'TransportUriConstruction', 'TransportScheme', 'TransportPort', 'TransportUserInfo',
            'TransportFragment', 'TransportHost', 'TransportHandlerConstruction', 'TransportRedirectPolicy',
            'TransportCookiePolicy', 'TransportCredentialPolicy', 'TransportProxyPolicy', 'TransportClientConstruction',
            'TransportTimeoutConfiguration', 'TransportMethodConstruction', 'TransportRequestConstruction', 'TransportBufferConstruction',
            'TransportHeaderConstruction', 'TransportBodyConstruction', 'TransportSend', 'TransportAdvertisedLimit',
            'TransportDeadlineConstruction', 'TransportStreamOpen', 'TransportReadBufferConstruction', 'TransportRead',
            'TransportStreamedLimit', 'TransportBufferWrite', 'TransportLocationRead', 'TransportResponseProjection',
            'TransportUtf8Decode', 'TransportStreamDispose', 'TransportResponseDispose', 'TransportDeadlineDispose',
            'TransportBufferDispose', 'TransportRequestDispose', 'TransportClientDispose'
        )
        'AuthorizationRequest/TransportFailure' = @(
            'TransportUriConstruction', 'TransportScheme', 'TransportPort', 'TransportUserInfo',
            'TransportFragment', 'TransportHost', 'TransportHandlerConstruction', 'TransportRedirectPolicy',
            'TransportCookiePolicy', 'TransportCredentialPolicy', 'TransportProxyPolicy', 'TransportClientConstruction',
            'TransportTimeoutConfiguration', 'TransportMethodConstruction', 'TransportRequestConstruction', 'TransportBufferConstruction',
            'TransportHeaderConstruction', 'TransportBodyConstruction', 'TransportSend', 'TransportAdvertisedLimit',
            'TransportDeadlineConstruction', 'TransportStreamOpen', 'TransportReadBufferConstruction', 'TransportRead',
            'TransportStreamedLimit', 'TransportBufferWrite', 'TransportLocationRead', 'TransportResponseProjection',
            'TransportUtf8Decode', 'TransportStreamDispose', 'TransportResponseDispose', 'TransportDeadlineDispose',
            'TransportBufferDispose', 'TransportRequestDispose', 'TransportClientDispose'
        )
        'TokenRequest/TransportFailure' = @(
            'TransportUriConstruction', 'TransportScheme', 'TransportPort', 'TransportUserInfo',
            'TransportFragment', 'TransportHost', 'TransportHandlerConstruction', 'TransportRedirectPolicy',
            'TransportCookiePolicy', 'TransportCredentialPolicy', 'TransportProxyPolicy', 'TransportClientConstruction',
            'TransportTimeoutConfiguration', 'TransportMethodConstruction', 'TransportRequestConstruction', 'TransportBufferConstruction',
            'TransportHeaderConstruction', 'TransportBodyConstruction', 'TransportSend', 'TransportAdvertisedLimit',
            'TransportDeadlineConstruction', 'TransportStreamOpen', 'TransportReadBufferConstruction', 'TransportRead',
            'TransportStreamedLimit', 'TransportBufferWrite', 'TransportLocationRead', 'TransportResponseProjection',
            'TransportUtf8Decode', 'TransportStreamDispose', 'TransportResponseDispose', 'TransportDeadlineDispose',
            'TransportBufferDispose', 'TransportRequestDispose', 'TransportClientDispose'
        )
        'UserInfoRequest/TransportFailure' = @(
            'TransportUriConstruction', 'TransportScheme', 'TransportPort', 'TransportUserInfo',
            'TransportFragment', 'TransportHost', 'TransportHandlerConstruction', 'TransportRedirectPolicy',
            'TransportCookiePolicy', 'TransportCredentialPolicy', 'TransportProxyPolicy', 'TransportClientConstruction',
            'TransportTimeoutConfiguration', 'TransportMethodConstruction', 'TransportRequestConstruction', 'TransportBufferConstruction',
            'TransportHeaderConstruction', 'TransportBodyConstruction', 'TransportSend', 'TransportAdvertisedLimit',
            'TransportDeadlineConstruction', 'TransportStreamOpen', 'TransportReadBufferConstruction', 'TransportRead',
            'TransportStreamedLimit', 'TransportBufferWrite', 'TransportLocationRead', 'TransportResponseProjection',
            'TransportUtf8Decode', 'TransportStreamDispose', 'TransportResponseDispose', 'TransportDeadlineDispose',
            'TransportBufferDispose', 'TransportRequestDispose', 'TransportClientDispose'
        )
    }
}
