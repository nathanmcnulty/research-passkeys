function Initialize-EntraRegistrationRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $headers = Get-EntraRegistrationHeaders -Context $Context -IncludeToken -IncludeSession
    $response = Invoke-EntraRegistrationRestMethod -Uri "$($Context.RedirectUri)/api/authenticationmethods/new" `
        -Method POST -Headers $headers -ContentType 'application/json' -Body '{"Type":18}' -WebSession $Context.WebSession
    if ($response.ErrorCode -and $response.ErrorCode -ne 0) { throw 'Passkey initialization was rejected by the service.' }
    $data = if ($response.Data -is [string]) { $response.Data | ConvertFrom-Json -ErrorAction Stop } else { $response.Data }
    $request = $data.requestData
    foreach ($name in @('canary', 'serverChallenge', 'userId')) {
        if ([string]::IsNullOrWhiteSpace([string]$request.$name)) { throw "Passkey initialization omitted $name." }
    }
    $postBack = if ($request.postBackUrl) { [string]$request.postBackUrl } else { "$($Context.RedirectUri)/api/post/newfido" }
    $provision = if ($data.provisionUrl) { [string]$data.provisionUrl } else { "https://login.microsoft.com/$($Context.TenantId)/fido/create" }
    $null = Assert-EntraKeyVaultRegistrationUri -Uri $postBack -RedirectUri $Context.RedirectUri
    $null = Assert-EntraKeyVaultRegistrationUri -Uri $provision -RedirectUri $Context.RedirectUri -Provisioning
    [ordered]@{
        Canary = [string]$request.canary
        ServerChallenge = [string]$request.serverChallenge
        UserHandle = [string]$request.userId
        ProvisionUrl = $provision
        PostBackUrl = $postBack
        CorrelationId = [guid]::NewGuid().ToString()
        ExcludeCredentials = if ($request.ExcludeNextGenCredentialsJSON) { [string]$request.ExcludeNextGenCredentialsJSON } else { '[]' }
        PostInfo = ''
        RedirectUrl = ''
    }
}

function Submit-EntraRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Request,
        [Parameter(Mandatory)]$Attestation,
        [Parameter(Mandatory)][string]$DisplayName
    )
    $null = Assert-EntraKeyVaultRegistrationUri -Uri $Request.ProvisionUrl -RedirectUri $Context.RedirectUri -Provisioning
    $null = Assert-EntraKeyVaultRegistrationUri -Uri $Request.PostBackUrl -RedirectUri $Context.RedirectUri
    $postBack = Add-EntraKeyVaultRegistrationQuery -Uri $Request.PostBackUrl -CorrelationId $Request.CorrelationId -IncludeRegion
    $createBody = ConvertTo-EntraRegistrationForm ([ordered]@{
        correlationId = $Request.CorrelationId; canary = $Request.Canary
        ExcludeNextGenCredentialsJSON = $Request.ExcludeCredentials
        memberName = $Context.UserPrincipalName; postBackUrl = $postBack
        serverChallenge = $Request.ServerChallenge; userDisplayName = $DisplayName
        userIconUrl = ''; userId = $Request.UserHandle
    })
    $createUri = Add-EntraKeyVaultRegistrationQuery -Uri $Request.ProvisionUrl -CorrelationId $Request.CorrelationId
    $Context.Stage = 'ChallengeSubmission'
    $created = Invoke-EntraRegistrationWebRequest -Uri $createUri -Method POST -Body $createBody `
        -ContentType 'application/x-www-form-urlencoded' -WebSession $Context.WebSession
    if ([int]$created.StatusCode -lt 200 -or [int]$created.StatusCode -ge 300) {
        throw 'FIDO challenge registration failed; refusing to finalize an unconfirmed ceremony.'
    }
    $fidoFields = [ordered]@{
        canary = $Request.Canary; credentialDeviceType = 'singleDevice'; credentialBackedUp = 'false'
        attestationParseError = ''; error_code = ''; suberror_code = ''; i19 = ''
        clientDataJson = $Attestation.ClientDataJson; attestationObject = $Attestation.AttestationObject
        credentialId = $Attestation.CredentialId; clientExtensionResults = $Attestation.ClientExtensionResults
    }
    foreach ($field in @('Authenticator', 'Transports', 'AAGuid')) {
        $present = if ($Attestation -is [System.Collections.IDictionary]) { $Attestation.Contains($field) } else { $null -ne $Attestation.PSObject.Properties[$field] }
        if ($present) { $fidoFields[$field.ToLowerInvariant()] = [string]$Attestation.$field }
    }
    $body = ConvertTo-EntraRegistrationForm $fidoFields
    $Context.Stage = 'CredentialSubmission'
    $Context.EnrollmentStatus = 'Unconfirmed'
    $response = Invoke-EntraRegistrationWebRequest -Uri $postBack -Method POST -Body $body `
        -ContentType 'application/x-www-form-urlencoded' -WebSession $Context.WebSession `
        -Headers @{ Origin = 'https://login.microsoft.com'; Referer = 'https://login.microsoft.com/' }
    if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
        $location = [string]$response.Headers.Location
        if (-not $location) { throw 'FIDO callback redirect omitted its destination.' }
        $target = [uri]::new([uri]$postBack, $location)
        $null = Assert-EntraKeyVaultRegistrationUri -Uri $target.AbsoluteUri -RedirectUri $Context.RedirectUri
        $Request.RedirectUrl = $target.AbsoluteUri
        # Parse the fragment using the same caller-owned state as HTML callbacks.
        $encoded = [System.Web.HttpUtility]::HtmlEncode($target.AbsoluteUri)
        Update-EntraKeyVaultRegistrationState -State $Request -Content "<div id=`"redirectUrl`" data-content=`"$encoded`">"
    } elseif ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw 'FIDO callback request failed.'
    } else {
        if ($response.Content -match '(?s)\$Config\s*=\s*(\{.*?\});') {
            $config = $matches[1] | ConvertFrom-Json -ErrorAction Stop
            if ($config.iErrorCode -and $config.iErrorCode -ne 0) { throw 'FIDO callback rejected registration.' }
        }
        Update-EntraKeyVaultRegistrationState -State $Request -Content $response.Content
    }
    if ($Request.RedirectUrl) {
        $nav = [uriBuilder]::new([string]$Request.RedirectUrl); $nav.Fragment = ''
        $null = Assert-EntraKeyVaultRegistrationUri -Uri $nav.Uri.AbsoluteUri -RedirectUri $Context.RedirectUri
        try {
            $page = Invoke-EntraRegistrationWebRequest -Uri $nav.Uri.AbsoluteUri -WebSession $Context.WebSession
            if ([int]$page.StatusCode -eq 200 -and -not $Request.PostInfo) {
                Update-EntraKeyVaultRegistrationState -State $Request -Content $page.Content
            }
        } catch { Write-Verbose 'Security-info navigation did not refresh registration state.' }
    }
    Update-EntraKeyVaultVerificationSession -Context $Context
    $Context.Stage = 'EnrollmentVerification'
    Invoke-EntraKeyVaultRegistrationVerification -Context $Context -Request $Request -Attestation $Attestation -DisplayName $DisplayName
}
