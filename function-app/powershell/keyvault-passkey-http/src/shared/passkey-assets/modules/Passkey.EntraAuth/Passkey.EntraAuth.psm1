function ConvertTo-UrlEncodedFormBody {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Fields
    )

    return ($Fields.GetEnumerator() |
        Where-Object { -not [string]::IsNullOrEmpty([string]$_.Value) } |
        ForEach-Object {
            "$([System.Web.HttpUtility]::UrlEncode([string]$_.Key))=$([System.Web.HttpUtility]::UrlEncode([string]$_.Value))"
        }) -join '&'
}

function Resolve-PasskeyAbsoluteUri {
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [string]$Location
    )

    if ($Location -match '^https?://') {
        return $Location
    }

    $base = [System.Uri]$BaseUri
    if ($Location.StartsWith('/')) {
        return "$($base.Scheme)://$($base.Host)$Location"
    }

    return ([System.Uri]::new($base, $Location)).AbsoluteUri
}

function Get-PasskeyEstsConfigFromHtmlContent {
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $configMatch = [regex]::Match(
        $Content,
        '\$Config=(\{.*?\});',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if (-not $configMatch.Success) {
        return $null
    }

    return $configMatch.Groups[1].Value | ConvertFrom-Json
}

function Add-EstsCookiesToWebSession {
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory)]
        $Response
    )

    try {
        foreach ($header in $Response.Headers.GetValues('Set-Cookie')) {
            if ($header -match '(ESTSAUTH[^=]*)=([^;]+)') {
                $WebSession.Cookies.Add([System.Net.Cookie]::new($matches[1], $matches[2], "/", ".login.microsoftonline.com"))
            }
        }
    } catch {
    }
}

function Add-PasskeyBrowserHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    if (-not $Headers.ContainsKey('User-Agent')) {
        $Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0'
    }

    if (-not $Headers.ContainsKey('Accept')) {
        $Headers['Accept'] = '*/*'
    }

    if (-not $Headers.ContainsKey('Accept-Language')) {
        $Headers['Accept-Language'] = 'en-US'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua')) {
        $Headers['sec-ch-ua'] = '"Chromium";v="148", "Microsoft Edge";v="148", "Not_A Brand";v="99"'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua-mobile')) {
        $Headers['sec-ch-ua-mobile'] = '?0'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua-platform')) {
        $Headers['sec-ch-ua-platform'] = '"Windows"'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Dest')) {
        $Headers['Sec-Fetch-Dest'] = 'empty'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Mode')) {
        $Headers['Sec-Fetch-Mode'] = 'cors'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Site')) {
        $Headers['Sec-Fetch-Site'] = 'same-origin'
    }
}

function Invoke-PasskeyTapPkceLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Authority,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$RedirectUri,

        [Parameter(Mandatory)]
        [string]$TokenScope,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$Tap,

        [Parameter(Mandatory)]
        [string]$CodeChallenge,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [int]$MaxRedirects = 15
    )

    Write-Host "  ✓ PKCE generated" -ForegroundColor Green

    $state = [guid]::NewGuid().ToString()
    $authUrl = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/authorize?" + `
        "client_id=$ClientId" + `
        "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" + `
        "&scope=$([System.Web.HttpUtility]::UrlEncode($TokenScope))" + `
        "&response_type=code" + `
        "&response_mode=fragment" + `
        "&prompt=login" + `
        "&login_hint=$([System.Web.HttpUtility]::UrlEncode($UserPrincipalName))" + `
        "&code_challenge=$CodeChallenge" + `
        "&code_challenge_method=S256" + `
        "&state=$state"

    Write-Host "  Loading login page..." -ForegroundColor Yellow
    $loginPage = Invoke-WebRequest -Uri $authUrl -UseBasicParsing -MaximumRedirection 10 -WebSession $WebSession
    if ($loginPage.StatusCode -ne 200) {
        throw "Expected login page (200), got $($loginPage.StatusCode)"
    }

    $config = Get-PasskeyEstsConfigFromHtmlContent -Content $loginPage.Content
    if ($null -eq $config) {
        throw "Could not extract `$Config from login page."
    }

    if ($config.pgid -ne 'ConvergedSignIn') {
        throw "Unexpected page: $($config.pgid). Error: $($config.strServiceExceptionMessage)"
    }

    $flowToken = $config.sFT
    $sCtx = $config.sCtx
    $canary = $config.canary
    $apiCanary = $config.apiCanary
    $sessionId = $config.sessionId
    $urlPost = $config.urlPost

    Write-Host "  ✓ Login page loaded (session=$sessionId)" -ForegroundColor Green
    Write-Host "  Calling GetCredentialType..." -ForegroundColor Yellow

    $gctBody = @{
        username             = $UserPrincipalName
        isOtherIdpSupported  = $false
        checkPhones          = $false
        isRemoteNGCSupported = $true
        isCookieBannerShown  = $false
        isFidoSupported      = $true
        originalRequest      = $sCtx
        flowToken            = $flowToken
    } | ConvertTo-Json -Compress

    $gctHeaders = @{
        canary       = $apiCanary
        hpgrequestid = $sessionId
        hpgact       = '1800'
        hpgid        = '1104'
    }

    try {
        $gctResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US" `
            -Method POST -Body $gctBody -ContentType "application/json" -Headers $gctHeaders

        if ($gctResp.FlowToken) {
            $flowToken = $gctResp.FlowToken
            Write-Host "  ✓ GetCredentialType OK (flowToken updated)" -ForegroundColor Green
        } else {
            Write-Host "  ✓ GetCredentialType OK" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ⚠ GetCredentialType failed (continuing without): $_" -ForegroundColor DarkYellow
    }

    Write-Host "  Submitting TAP to login endpoint..." -ForegroundColor Yellow
    $loginBody = @{
        login             = $UserPrincipalName
        loginfmt          = $UserPrincipalName
        accesspass        = $Tap
        ps                = '56'
        psRNGCDefaultType = '1'
        psRNGCEntropy     = ''
        psRNGCSLK         = $flowToken
        canary            = $canary
        ctx               = $sCtx
        hpgrequestid      = $sessionId
        flowToken         = $flowToken
        PPSX              = ''
        NewUser           = '1'
        FoundMSAs         = ''
        fspost            = '0'
        i21               = '0'
        CookieDisclosure  = '0'
        IsFidoSupported   = '1'
        isSignupPost      = '0'
        DfpArtifact       = ''
        i19               = '10000'
    }

    $currentUrl = if ([string]::IsNullOrWhiteSpace($urlPost)) {
        "https://login.microsoftonline.com/common/login"
    } else {
        Resolve-PasskeyAbsoluteUri -BaseUri $authUrl -Location $urlPost
    }
    $currentMethod = 'POST'
    $currentBody = ConvertTo-UrlEncodedFormBody -Fields $loginBody
    $currentContentType = 'application/x-www-form-urlencoded'

    for ($redirectCount = 0; $redirectCount -lt $MaxRedirects; $redirectCount++) {
        try {
            $requestParameters = @{
                Uri                = $currentUrl
                Method             = $currentMethod
                WebSession         = $WebSession
                MaximumRedirection = 0
                UseBasicParsing    = $true
            }

            if ($currentMethod -eq 'POST' -and $currentBody) {
                $requestParameters['Body'] = $currentBody
                $requestParameters['ContentType'] = $currentContentType
            }

            $response = Invoke-WebRequest @requestParameters -ErrorAction Stop
            if ($response.StatusCode -ne 200) {
                throw "Unexpected non-redirect response status $($response.StatusCode)"
            }

            if ($response.Content -match 'action="([^"]+)"') {
                $formAction = $matches[1]
                $hiddenFields = [regex]::Matches($response.Content, '<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"')
                $formPayload = [ordered]@{}
                foreach ($hiddenField in $hiddenFields) {
                    $formPayload[$hiddenField.Groups[1].Value] = $hiddenField.Groups[2].Value
                }

                if ($formAction -and $formPayload.Count -gt 0) {
                    $currentUrl = Resolve-PasskeyAbsoluteUri -BaseUri $currentUrl -Location $formAction
                    $currentMethod = 'POST'
                    $currentBody = ConvertTo-UrlEncodedFormBody -Fields $formPayload
                    $currentContentType = 'application/x-www-form-urlencoded'
                    Write-Host "    → Following form POST to: $($currentUrl.Substring(0, [Math]::Min(80, $currentUrl.Length)))..." -ForegroundColor DarkGray
                    continue
                }
            }

            $responseConfig = Get-PasskeyEstsConfigFromHtmlContent -Content $response.Content
            if ($null -ne $responseConfig) {
                if ($responseConfig.strServiceExceptionMessage) {
                    throw "Login page error: $($responseConfig.strServiceExceptionMessage)"
                }

                if ($responseConfig.pgid -eq 'ConvergedSignIn') {
                    throw "Returned to login page. The TAP may be invalid or expired."
                }

                if (($responseConfig.pgid -match '(?i)kmsi') -or ([string]$responseConfig.urlPost -match '(?i)kmsi')) {
                    $kmsiUrlPost = [string]$responseConfig.urlPost
                    if ([string]::IsNullOrWhiteSpace($kmsiUrlPost)) {
                        $kmsiUrlPost = '/kmsi'
                    }

                    $kmsiFields = [ordered]@{
                        LoginOptions = '1'
                        ctx          = [string]$responseConfig.sCtx
                        flowToken    = [string]$responseConfig.sFT
                        canary       = [string]$responseConfig.canary
                        hpgrequestid = [string]$responseConfig.sessionId
                    }

                    $currentUrl = Resolve-PasskeyAbsoluteUri -BaseUri $currentUrl -Location $kmsiUrlPost
                    $currentMethod = 'POST'
                    $currentBody = ConvertTo-UrlEncodedFormBody -Fields $kmsiFields
                    $currentContentType = 'application/x-www-form-urlencoded'
                    Write-Host "    → Answering KMSI page ('$($responseConfig.pgid)') with LoginOptions=1..." -ForegroundColor DarkGray
                    continue
                }

                throw "Unhandled ESTS interrupt page '$($responseConfig.pgid)' during login."
            }

            throw "Unexpected 200 response at redirect step $redirectCount. Content length: $($response.Content.Length)"
        } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -ge 300 -and $statusCode -lt 400) {
                $location = $_.Exception.Response.Headers.Location.ToString()
                $location = Resolve-PasskeyAbsoluteUri -BaseUri $currentUrl -Location $location
                Add-EstsCookiesToWebSession -WebSession $WebSession -Response $_.Exception.Response

                if ($location -match '[#?&]code=([^&#]+)') {
                    $authCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                    Write-Host "  ✓ TAP login successful! Got auth code (len=$($authCode.Length))" -ForegroundColor Green
                    return $authCode
                }

                if ($location -match 'error=([^&#]+)') {
                    $errorCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                    $errorDescription = ''
                    if ($location -match 'error_description=([^&#]+)') {
                        $errorDescription = [System.Web.HttpUtility]::UrlDecode($matches[1])
                    }

                    throw "Login failed: $errorCode - $errorDescription"
                }

                Write-Host "    → 302 to: $($location.Substring(0, [Math]::Min(80, $location.Length)))..." -ForegroundColor DarkGray
                $currentUrl = $location
                $currentMethod = 'GET'
                $currentBody = $null
                continue
            }

            throw
        }
    }

    throw "Failed to get auth code after $MaxRedirects redirect steps."
}

Export-ModuleMember -Function Add-PasskeyBrowserHeaders, Invoke-PasskeyTapPkceLogin
