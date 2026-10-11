# Public metadata transport: fixed HTTPS origin, no redirects/cookies, bounded reads.
function Invoke-EntraPasskeyMetadataDownload {
    [CmdletBinding()]
    param(
        [ValidateRange(1024, 33554432)][int]$MaximumBytes = 16777216,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 30
    )
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.UseDefaultCredentials = $false
    $handler.MaxResponseHeadersLength = 32
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $cancellation = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
    $response = $null; $stream = $null; $buffered = $null
    try {
        $response = $client.GetAsync('https://mds3.fidoalliance.org/', [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancellation.Token).GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne 200) { throw 'Metadata endpoint did not return HTTP 200; redirects are refused.' }
        if ($response.Content.Headers.ContentLength -gt $MaximumBytes) { throw 'Metadata download exceeded its size limit.' }
        $stream = $response.Content.ReadAsStreamAsync($cancellation.Token).GetAwaiter().GetResult()
        $buffered = [IO.MemoryStream]::new()
        $buffer = [byte[]]::new(8192)
        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
            if ($buffered.Length + $count -gt $MaximumBytes) { throw 'Metadata download exceeded its size limit.' }
            $buffered.Write($buffer, 0, $count)
        }
        return [Text.UTF8Encoding]::new($false, $true).GetString($buffered.ToArray()).Trim()
    } catch {
        # Do not expose remote response bodies or transport exceptions.
        throw 'Public metadata download failed, timed out, redirected, or exceeded its size limit.'
    } finally {
        if ($null -ne $buffered) { $buffered.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $cancellation.Dispose(); $client.Dispose(); $handler.Dispose()
    }
}

function ConvertFrom-EntraPasskeyMdsJwt {
    param([Parameter(Mandatory)][string]$Jwt, [ValidateRange(1024, 33554432)][int]$MaximumBytes = 16777216)
    if ([Text.Encoding]::UTF8.GetByteCount($Jwt) -gt $MaximumBytes) { throw 'Metadata input exceeded its size limit.' }
    $parts = $Jwt.Trim().Split('.')
    if ($parts.Count -ne 3 -or @($parts | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_-]+$' }).Count) {
        throw 'MDS input must be a three-part base64url JWT.'
    }
    try {
        $json = [Text.UTF8Encoding]::new($false, $true).GetString((ConvertFrom-Base64Url $parts[1]))
        return ($json | ConvertFrom-Json -Depth 100 -ErrorAction Stop)
    } catch { throw 'MDS JWT payload is malformed.' }
    # Deliberately no signature, certificate-chain, freshness or attestation-trust validation.
}
