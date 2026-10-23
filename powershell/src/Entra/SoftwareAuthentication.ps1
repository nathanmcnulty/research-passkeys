function Invoke-EntraRegistrationTapAuthentication {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][object]$TAP,
        [Parameter(Mandatory)][string]$UserPrincipalName, [AllowNull()][string]$TenantId)
    $Context.Stage = 'TenantDiscovery'
    $TenantId = Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserPrincipalName
    $tapText = ConvertTo-PlainTextValue $TAP
    if ([string]::IsNullOrWhiteSpace($tapText)) { throw 'TAP cannot be empty.' }
    try {
        $Context.Stage = 'TapSignInPage'
        $uri = Get-EntraRegistrationAuthorizeUri -Context $Context -Authority $TenantId.ToString() -UserPrincipalName $UserPrincipalName -Tap
        $response = Invoke-EntraRegistrationWebRequest -Uri $uri -WebSession $Context.WebSession
        if ([int]$response.StatusCode -ne 200) { throw 'Registration sign-in page was not returned.' }
        $config = Get-EntraRegistrationPageConfig -Content $response.Content
        if ($config.pgid -ne 'ConvergedSignIn' -or -not $config.sFT -or -not $config.sCtx) { throw 'Unexpected registration sign-in page.' }
        $Context.Stage = 'CredentialType'
        $flowToken = $config.sFT
        try {
        $gct = Invoke-EntraRegistrationRestMethod -Uri 'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US' `
            -Method POST -Body (@{
                username = $UserPrincipalName; isOtherIdpSupported = $false; checkPhones = $false
                isRemoteNGCSupported = $true; isCookieBannerShown = $false; isFidoSupported = $true
                originalRequest = $config.sCtx; flowToken = $config.sFT
            } | ConvertTo-Json -Compress) -ContentType 'application/json' `
            -Headers @{ canary = $config.apiCanary; hpgrequestid = $config.sessionId; hpgact = '1800'; hpgid = '1104' }
        if ($gct.FlowToken -is [string] -and -not [string]::IsNullOrWhiteSpace($gct.FlowToken)) { $flowToken = $gct.FlowToken }
        } catch { Write-Verbose 'Credential-type discovery failed; continuing with the original sign-in flow token.' }
        $postUri = if ($config.urlPost) { [uri]::new([uri]'https://login.microsoftonline.com/', [string]$config.urlPost) } else { [uri]'https://login.microsoftonline.com/common/login' }
        $null = Assert-EntraRegistrationUri $postUri.AbsoluteUri
        if ($postUri.Host -ne 'login.microsoftonline.com') { throw 'Unexpected TAP sign-in destination.' }
        $body = ConvertTo-EntraRegistrationForm @{
            login = $UserPrincipalName; loginfmt = $UserPrincipalName; accesspass = $tapText; ps = '56'
            psRNGCDefaultType = '1'; psRNGCEntropy = ''; psRNGCSLK = $flowToken
            canary = $config.canary; ctx = $config.sCtx; hpgrequestid = $config.sessionId; flowToken = $flowToken
            PPSX = ''; NewUser = '1'; FoundMSAs = ''; fspost = '0'; i21 = '0'; CookieDisclosure = '0'
            IsFidoSupported = '1'; isSignupPost = '0'; DfpArtifact = ''; i19 = '10000'
        }
        $Context.Stage = 'TapAuthorization'
        $code = Invoke-EntraRegistrationAuthorization -Context $Context -Uri $postUri.AbsoluteUri -Method POST -Body $body
        $Context.Stage = 'TokenExchange'
        return Complete-EntraRegistrationTokenExchange -Context $Context -Authority $TenantId.ToString() -Code $code `
            -TenantId $TenantId.ToString() -UserPrincipalName $UserPrincipalName
    } finally { $tapText = $null; $body = $null }
}

function Invoke-EntraRegistrationCookieAuthentication {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][object]$ESTSAuthCookie,
        [AllowNull()][string]$TenantId)
    $authority = 'organizations'
    if ($TenantId) {
        $tenant = [guid]::Empty
        if (-not [guid]::TryParse($TenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) { throw 'TenantId must be a nonempty GUID.' }
        $authority = $tenant.ToString()
    }
    $cookie = ConvertTo-PlainTextValue $ESTSAuthCookie
    if ([string]::IsNullOrWhiteSpace($cookie) -or $cookie -match '[\r\n;]') { throw 'ESTS cookie value is empty or invalid.' }
    try {
        foreach ($name in @('ESTSAUTH', 'ESTSAUTHPERSISTENT')) {
            $Context.WebSession.Cookies.Add([Net.Cookie]::new($name, $cookie, '/', '.login.microsoftonline.com'))
        }
        $uri = Get-EntraRegistrationAuthorizeUri -Context $Context -Authority $authority
        $code = Invoke-EntraRegistrationAuthorization -Context $Context -Uri $uri
        return Complete-EntraRegistrationTokenExchange -Context $Context -Authority $authority -Code $code -TenantId $TenantId
    } finally { $cookie = $null }
}

function Clear-EntraRegistrationContext {
    param([AllowNull()]$Context)
    if ($null -ne $Context) {
        foreach ($name in @('Token', 'RefreshToken', 'CodeVerifier', 'SessionCtxV2', 'WebSession')) { $Context.$name = $null }
    }
}
