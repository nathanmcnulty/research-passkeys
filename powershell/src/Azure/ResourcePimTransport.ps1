function Assert-AzureArmUri {
    param([Parameter(Mandatory)][string]$Uri)
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or
        $parsed.Port -ne 443 -or
        $parsed.UserInfo -or
        $parsed.Host -ne 'management.azure.com') {
        throw 'Refusing untrusted Azure Resource Manager endpoint.'
    }
    return $parsed
}

function Resolve-AzurePimScope {
    param([Parameter(Mandatory)][string]$Scope)
    $trimmed = $Scope.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'Scope cannot be empty.'
    }
    if ($trimmed.Contains('?') -or $trimmed.Contains('#') -or $trimmed -match '\s' -or $trimmed.Split('/') -contains '..') {
        throw 'Scope must be a clean Azure Resource Manager scope path without query, fragment, whitespace, or parent traversal.'
    }
    if ($trimmed -eq '/') {
        return '/'
    }
    $normalized = '/' + $trimmed.Trim('/')
    if ($normalized -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$' -or
        $normalized -match '^/subscriptions/[^/]+$' -or
        $normalized -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$' -or
        $normalized -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/.+$' -or
        $normalized -match '^/subscriptions/[^/]+/providers/[^/]+/.+$') {
        return $normalized
    }
    throw "Unsupported or malformed Azure Resource Manager scope: '$Scope'."
}

function New-AzurePimArmUri {
    param(
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$ProviderPath,
        [AllowNull()][string]$QueryString
    )
    $normalizedScope = Resolve-AzurePimScope -Scope $Scope
    $relativePath = $ProviderPath.TrimStart('/')
    $prefix = if ($normalizedScope -eq '/') { '' } else { $normalizedScope }
    $baseUri = "https://management.azure.com$prefix/providers/Microsoft.Authorization/$relativePath"
    $fullUri = if ([string]::IsNullOrWhiteSpace($QueryString)) {
        $baseUri
    } else {
        $baseUri + '?' + $QueryString.TrimStart('?')
    }
    $null = Assert-AzureArmUri -Uri $fullUri
    return $fullUri
}

function ConvertTo-AzurePimIsoDuration {
    param([Parameter(Mandatory)][string]$Duration)
    $trimmed = $Duration.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'Duration cannot be empty.'
    }
    $span = [TimeSpan]::Zero
    if ($trimmed.StartsWith('P', [System.StringComparison]::OrdinalIgnoreCase)) {
        try {
            $span = [System.Xml.XmlConvert]::ToTimeSpan($trimmed.ToUpperInvariant())
        } catch {
            throw "Duration '$Duration' is not a valid ISO 8601 duration (for example PT1H or PT30M)."
        }
    } elseif ($trimmed.Contains(':')) {
        if (-not [TimeSpan]::TryParseExact($trimmed, 'c', [System.Globalization.CultureInfo]::InvariantCulture, [ref]$span)) {
            throw "Duration '$Duration' is not a valid TimeSpan or ISO 8601 duration (for example PT1H or 01:00:00)."
        }
    } else {
        throw "Duration '$Duration' must be an ISO 8601 duration (for example PT1H or PT30M) or hh:mm:ss TimeSpan."
    }
    if ($span -le [TimeSpan]::Zero) {
        throw 'Duration must be greater than zero.'
    }
    return [System.Xml.XmlConvert]::ToString($span)
}

function Get-AzurePimClaimsChallengeFromText {
    param([AllowNull()][string]$RawChallenge)
    $trimmed = Normalize-OptionalString $RawChallenge
    if (-not $trimmed) {
        return $null
    }
    $decoded = if ($trimmed.StartsWith('{')) {
        $trimmed
    } else {
        $base64 = $trimmed.Replace('-', '+').Replace('_', '/')
        $remainder = $base64.Length % 4
        if ($remainder -ne 0) {
            $base64 = $base64 + ('=' * (4 - $remainder))
        }
        try {
            $bytes = [Convert]::FromBase64String($base64)
            [System.Text.Encoding]::UTF8.GetString($bytes)
        } catch {
            throw 'ARM claims challenge could not be Base64-decoded.'
        }
    }
    try {
        $parsed = $decoded | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($parsed -isnot [System.Collections.IDictionary]) {
            throw 'Claims challenge must decode to a JSON object.'
        }
    } catch {
        throw 'ARM claims challenge did not contain a valid JSON object.'
    }
    return $decoded
}

function Get-AzurePimClaimsChallengeFromResponse {
    param(
        [AllowNull()][string[]]$WwwAuthenticate,
        [AllowNull()][string]$Content
    )
    if ($WwwAuthenticate) {
        foreach ($headerValue in $WwwAuthenticate) {
            if ([string]::IsNullOrWhiteSpace($headerValue)) {
                continue
            }
            $quotedMatch = [regex]::Match($headerValue, '(?:^|[\s,])claims\s*=\s*"([^"]+)"')
            if ($quotedMatch.Success) {
                return Get-AzurePimClaimsChallengeFromText -RawChallenge $quotedMatch.Groups[1].Value
            }
            $unquotedMatch = [regex]::Match($headerValue, '(?:^|[\s,])claims\s*=\s*([^\s,]+)')
            if ($unquotedMatch.Success) {
                return Get-AzurePimClaimsChallengeFromText -RawChallenge $unquotedMatch.Groups[1].Value
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Content)) {
        try {
            $payload = $Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            if ($payload -is [System.Collections.IDictionary]) {
                $errorObj = if ($payload.ContainsKey('error') -and $payload.error -is [System.Collections.IDictionary]) {
                    $payload.error
                } else {
                    $payload
                }
                foreach ($key in @('claims', 'claimsChallenge', 'claims_challenge')) {
                    if ($errorObj.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$errorObj[$key])) {
                        return Get-AzurePimClaimsChallengeFromText -RawChallenge ([string]$errorObj[$key])
                    }
                }
            }
        } catch {
            # Non-JSON error bodies do not carry structured claims challenges.
        }
    }
    return $null
}

function Get-AzurePimSanitizedArmError {
    param(
        [Parameter(Mandatory)][int]$StatusCode,
        [AllowNull()][string]$Content,
        [AllowNull()][string]$RequestId
    )
    $code = $null
    $message = $null
    if (-not [string]::IsNullOrWhiteSpace($Content)) {
        try {
            $parsed = $Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            if ($parsed -is [System.Collections.IDictionary]) {
                $err = if ($parsed.ContainsKey('error') -and $parsed.error -is [System.Collections.IDictionary]) {
                    $parsed.error
                } else {
                    $parsed
                }
                $code = Normalize-OptionalString ([string]$err['code'])
                $message = Normalize-OptionalString ([string]$err['message'])
            }
        } catch {
            $message = $null
        }
    }
    if (-not $message) {
        $message = 'Azure Resource Manager returned an error response (raw details suppressed).'
    } else {
        # Guard against echoing any bearer-like token material from error text.
        $message = [regex]::Replace($message, '(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]')
        $message = [regex]::Replace($message, 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', '[REDACTED_JWT]')
    }
    $prefix = if ($code) { "HTTP $StatusCode ($code)" } else { "HTTP $StatusCode" }
    $suffix = if ($RequestId) { " [requestId=$RequestId]" } else { '' }
    return "$prefix`: $message$suffix"
}

function Invoke-AzureResourcePimHttpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT')][string]$Method,
        [Parameter(Mandatory)][object]$AccessToken,
        [AllowNull()][string]$Body,
        [AllowNull()][string]$UserAgent,
        [AllowNull()][string]$Proxy
    )
    $null = Assert-AzureArmUri -Uri $Uri
    $plainToken = ConvertTo-PlainTextValue $AccessToken
    if ([string]::IsNullOrWhiteSpace($plainToken)) {
        throw 'ARM access token cannot be empty.'
    }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
        $handler.UseProxy = $true
        $handler.Proxy = [System.Net.WebProxy]::new($Proxy)
    }
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $request = $null
    $response = $null
    try {
        if (-not [string]::IsNullOrWhiteSpace($UserAgent)) {
            $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', $UserAgent)
        }
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Uri)
        $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $plainToken)
        $null = $request.Headers.TryAddWithoutValidation('Accept', 'application/json')
        if ($null -ne $Body) {
            $request.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, 'application/json')
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $wwwAuth = [System.Collections.Generic.List[string]]::new()
        $rawWwwAuth = $null
        if ($response.Headers.TryGetValues('WWW-Authenticate', [ref]$rawWwwAuth)) {
            foreach ($entry in $rawWwwAuth) {
                $wwwAuth.Add([string]$entry)
            }
        }
        $requestId = $null
        $rawReqId = $null
        if ($response.Headers.TryGetValues('x-ms-request-id', [ref]$rawReqId)) {
            $requestId = ($rawReqId | Select-Object -First 1)
        }
        return [pscustomobject]@{
            StatusCode      = [int]$response.StatusCode
            Content         = $content
            WwwAuthenticate = @($wwwAuth)
            RequestId       = $requestId
        }
    } finally {
        $plainToken = $null
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}
