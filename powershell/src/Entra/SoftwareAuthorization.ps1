function Stop-EntraRegistrationAuthorization {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Category,
        [int]$HttpStatus, [AllowNull()]$Config, [AllowNull()][string]$ErrorText, [AllowNull()][string]$MissingField)
    $aadsts = $null; $service = 0
    # Extract identifiers only. Descriptions may contain credentials or identifying data.
    $text = if ($Config) { [string]$Config.strServiceExceptionMessage } else { $ErrorText }
    if ($text -cmatch '\b(AADSTS[0-9]{4,12})\b') { $aadsts = $matches[1] }
    $null = [int]::TryParse([string]$Config.iErrorCode, [ref]$service)
    $page = if ($Config.pgid -is [string] -and $Config.pgid -cin @('KmsiBroker','KmsiInterrupt','ConvergedSignIn','Consent','ConvergedConsent','CmsiInterrupt','ConvergedProofUp')) { $Config.pgid } else { 'Unknown' }
    $Context.AuthorizationFailure = [pscustomobject]@{ Category=$Category; HttpStatus=$HttpStatus; AadstsCode=$aadsts; ServiceErrorCode=$service; Page=$page; MissingField=$MissingField }
    $summary = switch ($Category) {
        'UnsupportedContinuation' { 'Unrecognized login continuation or consent/policy interrupt; manual review required.' }
        'RedirectLimit' { 'Registration authorization exceeded the redirect limit.' }
        'UntrustedRedirect' { 'Cross-origin or untrusted registration redirect refused; only allowed HTTPS origins are supported.' }
        default { "Registration authorization refused: $Category ($page); sensitive details suppressed." }
    }
    throw $summary
}

function Get-EntraRegistrationHtmlAttribute {
    param([Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$Name)
    # Attribute order, whitespace and either quote style are valid HTML. Duplicate attributes remain invalid.
    $pattern = '(?is)(?:^|\s)(?<name>[a-z_:][a-z0-9_:.-]*)\s*=\s*(?:"(?<value>[^"]*)"|''(?<value>[^'']*)''|(?<value>[^\s"''=<>`]+))'
    $values = @([regex]::Matches($Tag, $pattern) | Where-Object { $_.Groups['name'].Value -ieq $Name })
    if ($values.Count -gt 1) { throw 'Ambiguous continuation attribute.' }
    if ($values.Count -eq 0) { return $null }
    return [Web.HttpUtility]::HtmlDecode($values[0].Groups['value'].Value)
}

# Bounded OAuth continuation; only the fixed authentication-only KMSI target is eligible for form submission.
function Invoke-EntraRegistrationAuthorization {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET', [AllowNull()][string]$Body)
    $current = $Uri
    for ($step = 0; $step -lt 15; $step++) {
        $request = @{ Uri = $current; Method = $Method; WebSession = $Context.WebSession }
        if ($Method -eq 'POST') { $request.Body = $Body; $request.ContentType = 'application/x-www-form-urlencoded' }
        try { $response = Invoke-EntraRegistrationWebRequest @request }
        catch { Stop-EntraRegistrationAuthorization -Context $Context -Category TransportFailure }
        $status = [int]$response.StatusCode
        if ($status -in @(301, 302, 303, 307, 308)) {
            $locations = @($response.Headers.Location)
            if ($locations.Count -ne 1 -or [string]::IsNullOrWhiteSpace($locations[0])) { Stop-EntraRegistrationAuthorization -Context $Context -Category RedirectShape -HttpStatus $status }
            try {
                $next = [uri]::new([uri]$current, [string]$locations[0]).AbsoluteUri
                $nextUri = Assert-EntraRegistrationUri $next
            } catch { Stop-EntraRegistrationAuthorization -Context $Context -Category UntrustedRedirect -HttpStatus $status }
            $fields = [Web.HttpUtility]::ParseQueryString($nextUri.Query.TrimStart('?') + '&' + $nextUri.Fragment.TrimStart('#'))
            if ($fields['error']) { Stop-EntraRegistrationAuthorization -Context $Context -Category OAuthRejected -HttpStatus $status -ErrorText $fields['error_description'] }
            if ($fields['code']) {
                try { return Get-EntraRegistrationAuthorizationCode -Callback $next -ExpectedState $Context.State }
                catch { Stop-EntraRegistrationAuthorization -Context $Context -Category CallbackBinding -HttpStatus $status }
            }
            # Never forward a TAP/form through 307/308 to another origin.
            if ($status -in @(307, 308) -and $Method -eq 'POST') {
                if ($nextUri.Host -ne ([uri]$current).Host) { Stop-EntraRegistrationAuthorization -Context $Context -Category UntrustedRedirect -HttpStatus $status }
            } else { $Method = 'GET'; $Body = $null }
            $current = $next
            continue
        }
        if ($status -ne 200) { Stop-EntraRegistrationAuthorization -Context $Context -Category HttpFailure -HttpStatus $status }
        $config = $null
        if ($response.Content -match '(?s)\$Config\s*=') {
            try { $config = Get-EntraRegistrationPageConfig -Content $response.Content }
            catch { Stop-EntraRegistrationAuthorization -Context $Context -Category ConfigInvalid -HttpStatus $status }
            if ($config.strServiceExceptionMessage -or ($config.iErrorCode -and $config.iErrorCode -ne 0)) { Stop-EntraRegistrationAuthorization -Context $Context -Category ServiceRejected -HttpStatus $status -Config $config }
            if ($config.pgid -eq 'ConvergedSignIn') { Stop-EntraRegistrationAuthorization -Context $Context -Category SignInReturned -HttpStatus $status -Config $config }
            if ($config.pgid -isnot [string] -or $config.pgid -cnotin @('KmsiBroker', 'KmsiInterrupt')) { Stop-EntraRegistrationAuthorization -Context $Context -Category UnsupportedContinuation -HttpStatus $status -Config $config }
        }
        $formStarts = [regex]::Matches($response.Content, '(?is)<form\b')
        $forms = [regex]::Matches($response.Content, '(?is)(?<tag><form\b[^>]*>)(?<fields>.*?)</form\s*>')
        # The curated passkey login already supports this JS-only KMSI payload.
        # Require zero form starts, so malformed/ambiguous HTML cannot trigger a fallback.
        if ($config.pgid -ceq 'KmsiInterrupt' -and $response.Content -notmatch '(?is)<form\b') {
            foreach ($field in @('sCtx','sFT','canary','correlationId')) {
                if ($config.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($config.$field)) {
                    Stop-EntraRegistrationAuthorization -Context $Context -Category KmsiFieldsMissing -HttpStatus $status -Config $config -MissingField $field
                }
            }
            $current = 'https://login.microsoftonline.com/kmsi'; $Method = 'POST'
            $Body = ConvertTo-EntraRegistrationForm @{ LoginOptions=1; type=28; ctx=$config.sCtx; hpgrequestid=$config.correlationId; flowToken=$config.sFT; canary=$config.canary; i19=4130 }
            continue
        }
        if (-not $config -and $formStarts.Count -eq 0) { Stop-EntraRegistrationAuthorization -Context $Context -Category ConfigMissing -HttpStatus $status }
        if ($forms.Count -eq 0) { Stop-EntraRegistrationAuthorization -Context $Context -Category FormMissing -HttpStatus $status -Config $config }
        if ($forms.Count -ne 1 -or $formStarts.Count -ne 1) { Stop-EntraRegistrationAuthorization -Context $Context -Category FormAmbiguous -HttpStatus $status -Config $config }
        try { $action = Get-EntraRegistrationHtmlAttribute -Tag $forms[0].Groups['tag'].Value -Name action; $formMethod = Get-EntraRegistrationHtmlAttribute -Tag $forms[0].Groups['tag'].Value -Name method }
        catch { Stop-EntraRegistrationAuthorization -Context $Context -Category FormAmbiguous -HttpStatus $status -Config $config }
        if (-not $action) { Stop-EntraRegistrationAuthorization -Context $Context -Category FormAction -HttpStatus $status -Config $config -MissingField form.action }
        if ($formMethod -and $formMethod -ine 'post') { Stop-EntraRegistrationAuthorization -Context $Context -Category FormMethod -HttpStatus $status -Config $config }
        try { $nextUri = Assert-EntraRegistrationUri ([uri]::new([uri]$current, $action).AbsoluteUri) }
        catch { Stop-EntraRegistrationAuthorization -Context $Context -Category FormAction -HttpStatus $status -Config $config }
        if ($nextUri.Host -ne 'login.microsoftonline.com' -or
            (-not $config -and ($nextUri.AbsolutePath -cne '/kmsi' -or $nextUri.Query -or $nextUri.Fragment))) { Stop-EntraRegistrationAuthorization -Context $Context -Category FormAction -HttpStatus $status -Config $config }
        $fieldMarkup = $forms[0].Groups['fields'].Value
        if (-not $config -and $fieldMarkup -match '(?is)<(?:button|select|textarea)\b') { Stop-EntraRegistrationAuthorization -Context $Context -Category FormControls -HttpStatus $status -Config $config }
        $formFields = [ordered]@{}
        foreach ($inputTag in [regex]::Matches($fieldMarkup, '(?is)<input\b[^>]*>')) {
            try {
                $type = Get-EntraRegistrationHtmlAttribute -Tag $inputTag.Value -Name type
                $name = Get-EntraRegistrationHtmlAttribute -Tag $inputTag.Value -Name name
                $value = Get-EntraRegistrationHtmlAttribute -Tag $inputTag.Value -Name value
            } catch { Stop-EntraRegistrationAuthorization -Context $Context -Category InputAmbiguous -HttpStatus $status -Config $config }
            if ($type -ine 'hidden') {
                if (-not $config) { Stop-EntraRegistrationAuthorization -Context $Context -Category FormControls -HttpStatus $status -Config $config }
                continue
            }
            if ([string]::IsNullOrWhiteSpace($name)) { Stop-EntraRegistrationAuthorization -Context $Context -Category InputMissing -HttpStatus $status -Config $config -MissingField input.name }
            if ($null -eq $value) { Stop-EntraRegistrationAuthorization -Context $Context -Category InputMissing -HttpStatus $status -Config $config -MissingField input.value }
            if ($formFields.Contains($name)) { Stop-EntraRegistrationAuthorization -Context $Context -Category DuplicateField -HttpStatus $status -Config $config }
            $formFields[$name] = $value
        }
        if (-not $formFields.Count) { Stop-EntraRegistrationAuthorization -Context $Context -Category HiddenFieldsMissing -HttpStatus $status -Config $config }
        $current = $nextUri.AbsoluteUri; $Method = 'POST'; $Body = ConvertTo-EntraRegistrationForm $formFields
    }
    Stop-EntraRegistrationAuthorization -Context $Context -Category RedirectLimit
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
