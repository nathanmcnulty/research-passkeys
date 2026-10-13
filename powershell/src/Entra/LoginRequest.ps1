function Assert-EntraLoginUri {
    param([Parameter(Mandatory)][string]$Uri)
    $parsed = $null
    if (-not [uri]::TryCreate($Uri,[UriKind]::Absolute,[ref]$parsed) -or $parsed.Scheme -ne 'https' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Host -notin @('login.microsoftonline.com','login.microsoft.com','login.windows.net')) {
        throw 'Untrusted Entra login URL.'
    }
    return $parsed
}

function Invoke-EntraLoginWebRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][string]$Uri,[string]$Method='Get',$Body)
    $current = Assert-EntraLoginUri $Uri
    for ($redirects = 0; $redirects -le 10; $redirects++) {
        $args = @{Uri=$current.AbsoluteUri;Method=$Method;WebSession=$Context.Session;MaximumRedirection=0;SkipHttpErrorCheck=$true;UseBasicParsing=$true;ConnectionTimeoutSeconds=30;OperationTimeoutSeconds=30;Verbose=$false;Debug=$false}
        if ($Context.Proxy) { $args.Proxy=$Context.Proxy }
        if ($null -ne $Body) { $args.Body=$Body }
        $transportErrors = @()
        try {
            $responses = @(Invoke-WebRequest @args -ErrorAction SilentlyContinue -ErrorVariable transportErrors)
            if ($responses.Count -ne 1) { throw 'Login transport did not return one response.' }
            $response = $responses[0]
            foreach ($record in $transportErrors) {
                if ($record.FullyQualifiedErrorId -cne 'MaximumRedirectExceeded,Microsoft.PowerShell.Commands.InvokeWebRequestCommand' -or
                    [int]$response.StatusCode -notin @(301,302,303,307,308)) { throw 'Unexpected login transport error.' }
            }
        } catch { $Error.Remove($_); throw 'Entra login request failed; details suppressed.' }
        finally { foreach ($record in $transportErrors) { $Error.Remove($record) }; $transportErrors = $null }
        if ($response.StatusCode -ge 400) { throw 'Entra login request failed; details suppressed.' }
        if ($response.StatusCode -lt 300 -or $response.StatusCode -ge 400) { return $response }
        if ($redirects -eq 10) { throw 'Entra login exceeded the redirect limit.' }
        $locations = @($response.Headers.Location)
        if ($locations.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$locations[0])) { throw 'Entra login returned an invalid redirect.' }
        try {
            $next = [uri]::new($current,[string]$locations[0])
            $current = Assert-EntraLoginUri $next.AbsoluteUri
        } catch { $Error.Remove($_); throw 'Entra login returned an invalid or untrusted redirect; details suppressed.' }
        # Never re-post an assertion to a redirected target, including same-origin 307/308.
        if ([int]$response.StatusCode -in 307,308 -and $Method -ine 'Get') { throw 'Entra login refused an assertion-preserving redirect.' }
        $Method='Get';$Body=$null
    }
}

function Read-EntraLoginPage {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Response,[switch]$RequireConfig,[switch]$AllowNoSession)
    $content=[string]$Response.Content
    if ($content.Length -gt 2097152) { throw 'Entra login returned an oversized response.' }
    $start=-1
    $config=[regex]::Match($content,'\$Config\s*=\s*\{')
    if ($config.Success) { $start=$config.Index+$config.Length-1 }
    elseif ($content.TrimStart().StartsWith('{')) { $start=$content.IndexOf('{') }
    if ($start -lt 0) {
        if ($RequireConfig) { throw 'Entra login returned an invalid configuration.' }
        return @{}
    }
    $depth=0;$inString=$false;$escaped=$false;$end=-1
    for ($index=$start;$index -lt $content.Length;$index++) {
        $character=$content[$index]
        if ($inString) {
            if ($escaped) { $escaped=$false }
            elseif ($character -eq '\') { $escaped=$true }
            elseif ($character -eq '"') { $inString=$false }
        } elseif ($character -eq '"') { $inString=$true }
        elseif ($character -eq '{') { $depth++ }
        elseif ($character -eq '}') {
            $depth--
            if ($depth -eq 0) { $end=$index;break }
        }
    }
    if ($end -lt 0) { throw 'Entra login returned malformed configuration JSON.' }
    try { $state=$content.Substring($start,$end-$start+1) | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { throw 'Entra login returned malformed configuration JSON.' }
    if ($state -isnot [System.Collections.IDictionary]) { throw 'Entra login returned invalid configuration.' }
    # sso_reload can report no existing session (50058) while offering the requested
    # user's FIDO challenge. It is a sign-in start, not a rejected assertion.
    $noSession = $AllowNoSession -and $state.pgid -ceq 'ConvergedSignIn' -and [string]$state.sErrorCode -ceq '50058' -and
        $state.oGetCredTypeResult.Credentials.HasFido -eq $true -and
        -not [string]::IsNullOrWhiteSpace($state.sFidoChallenge) -and
        -not [string]::IsNullOrWhiteSpace($state.sFT) -and -not [string]::IsNullOrWhiteSpace($state.sCtx)
    if ($state.error -or ($state.sErrorCode -and -not $noSession) -or $state.strServiceExceptionMessage -or $state.sErrTxt -or $state.errorCode) { throw 'Entra login was denied by the server; details suppressed.' }
    return $state
}
