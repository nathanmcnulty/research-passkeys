function Assert-EntraKeyVaultRegistrationUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$RedirectUri,
        [switch]$Provisioning
    )
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or $parsed.UserInfo -or $parsed.Scheme -ne 'https' -or $parsed.Port -ne 443) {
        throw 'Refusing untrusted registration URL.'
    }
    if ($Provisioning) {
        if ($parsed.Host -notin @('login.microsoft.com', 'login.microsoftonline.com')) { throw 'Refusing untrusted provisionUrl.' }
    } elseif ($parsed.GetLeftPart([UriPartial]::Authority) -ine ([uri]$RedirectUri).GetLeftPart([UriPartial]::Authority)) {
        throw 'Refusing untrusted registration redirect or postBackUrl.'
    }
    $parsed.AbsoluteUri
}

function Add-EntraKeyVaultRegistrationQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$CorrelationId, [switch]$IncludeRegion)
    $builder = [uriBuilder]::new($Uri)
    $query = [System.Web.HttpUtility]::ParseQueryString($builder.Query)
    $query['cid'] = $CorrelationId
    if ($IncludeRegion) { $query['mysignins-region'] = 'westus2' }
    $builder.Query = $query.ToString()
    $builder.Uri.AbsoluteUri
}

function Update-EntraKeyVaultRegistrationState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [AllowEmptyString()][string]$Content)
    if ($Content -match '<div\s+id="context"\s+data-content="([^"]*)"') {
        $json = [System.Web.HttpUtility]::HtmlDecode($matches[1])
        try {
            $context = $json | ConvertFrom-Json -ErrorAction Stop
            if ($context.Canary) { $State.Canary = [string]$context.Canary }
            if ($context.PostInfo) { $State.PostInfo = [string]$context.PostInfo }
        } catch { Write-Verbose 'Registration response context could not be parsed.' }
    }
    if ($Content -match '<div\s+id="redirectUrl"\s+data-content="([^"]*)"') {
        $State.RedirectUrl = [System.Web.HttpUtility]::HtmlDecode($matches[1])
        $url = [uri]$State.RedirectUrl
        $values = [System.Web.HttpUtility]::ParseQueryString($url.Fragment.TrimStart('#'))
        if ($values['fidoProvisionSuccess']) { $State.Canary = $values['fidoProvisionSuccess'] }
        if ($values['postinfo']) { $State.PostInfo = $values['postinfo'] }
    }
    # State is caller-owned. No script/global variables are modified.
}

function New-EntraKeyVaultVerificationDataJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Template,
        [ValidateSet('empty', 'context')][string]$PostInfoMode = 'empty',
        [AllowEmptyString()][string]$PostInfo
    )
    $value = [ordered]@{}
    foreach ($name in @('Name', 'Canary', 'AttestationObject', 'ClientDataJson', 'CredentialId', 'ClientExtensionResults')) {
        $value[$name] = [string]$Template[$name]
    }
    $value.PostInfo = if ($PostInfoMode -eq 'context') { [string]$PostInfo } else { '' }
    $value.AAGuid = '00000000-0000-0000-0000-000000000000'
    $value.CredentialDeviceType = 'singleDevice'
    $value | ConvertTo-Json -Compress
}
