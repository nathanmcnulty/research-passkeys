using namespace System.Net

function Get-RequestBodyObject {
    param(
        [Parameter(Mandatory)]
        $Request
    )

    if ($null -eq $Request.Body) {
        return @{}
    }

    if ($Request.Body -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Request.Body)) {
            return @{}
        }

        return $Request.Body | ConvertFrom-Json -AsHashtable
    }

    if ($Request.Body -is [System.Collections.IDictionary]) {
        return $Request.Body
    }

    return ($Request.Body | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable)
}

function Get-RequestValue {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Body.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$Body[$name])) {
            return [string]$Body[$name]
        }

        $queryValue = $null
        if ($null -ne $Request.Query) {
            if ($Request.Query -is [System.Collections.IDictionary]) {
                if ($Request.Query.ContainsKey($name)) {
                    $queryValue = [string]$Request.Query[$name]
                }
            } else {
                $property = $Request.Query.PSObject.Properties[$name]
                if ($property) {
                    $queryValue = [string]$property.Value
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($queryValue)) {
            return $queryValue
        }
    }

    return $null
}

function Get-BodyValue {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Body.ContainsKey($name)) {
            return $Body[$name]
        }
    }

    return $null
}

function Get-RegistrationQueueName {
    $queueName = [Environment]::GetEnvironmentVariable('PASSKEY_REGISTRATION_QUEUE_NAME')
    if ([string]::IsNullOrWhiteSpace($queueName)) {
        return 'passkey-registration'
    }

    return $queueName
}

function Get-OktaRegistrationQueueName {
    $queueName = [Environment]::GetEnvironmentVariable('PASSKEY_OKTA_REGISTRATION_QUEUE_NAME')
    if ([string]::IsNullOrWhiteSpace($queueName)) {
        return 'okta-passkey-registration'
    }

    return $queueName
}

function Get-EstsAuthCookieFromSource {
    param(
        [Parameter()]
        $CookieSource
    )

    if ($null -eq $CookieSource) {
        return $null
    }

    if ($CookieSource -is [byte[]]) {
        $CookieSource = [System.Text.Encoding]::UTF8.GetString($CookieSource)
    }

    if ($CookieSource -is [string]) {
        $trimmed = $CookieSource.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            return $null
        }

        if ($trimmed.StartsWith('[') -or $trimmed.StartsWith('{') -or $trimmed.StartsWith('"')) {
            try {
                $parsed = $trimmed | ConvertFrom-Json -AsHashtable -Depth 20
                $nestedCookie = Get-EstsAuthCookieFromSource -CookieSource $parsed
                if (-not [string]::IsNullOrWhiteSpace($nestedCookie)) {
                    return $nestedCookie
                }
            } catch {
            }
        }

        foreach ($cookieName in @('ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT')) {
            $match = [regex]::Match($trimmed, "(?:^|;\s*)$cookieName=([^;]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($match.Success -and -not [string]::IsNullOrWhiteSpace($match.Groups[1].Value)) {
                return $match.Groups[1].Value.Trim()
            }
        }

        return $trimmed
    }

    if ($CookieSource -is [System.Collections.IDictionary]) {
        foreach ($name in @('estsAuth', 'estsAuthCookie', 'ESTSAUTH')) {
            if ($CookieSource.Contains($name) -and -not [string]::IsNullOrWhiteSpace([string]$CookieSource[$name])) {
                return [string]$CookieSource[$name]
            }
        }

        foreach ($name in @('cookies', 'cookieExport', 'cookieJson', 'cookieData', 'browserCookies', 'tokens', 'items')) {
            if ($CookieSource.Contains($name)) {
                $nestedCookie = Get-EstsAuthCookieFromSource -CookieSource $CookieSource[$name]
                if (-not [string]::IsNullOrWhiteSpace($nestedCookie)) {
                    return $nestedCookie
                }
            }
        }

        if ($CookieSource.Contains('name') -and $CookieSource.Contains('value')) {
            $cookieName = [string]$CookieSource['name']
            $cookieValue = [string]$CookieSource['value']
            if ($cookieName -and $cookieValue -and @('ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT') -contains $cookieName.ToUpperInvariant()) {
                return $cookieValue.Trim()
            }
        }

        return $null
    }

    if ($CookieSource -is [System.Collections.IEnumerable]) {
        $candidates = @{}
        foreach ($item in $CookieSource) {
            if ($item -is [System.Collections.IDictionary] -and $item.Contains('name') -and $item.Contains('value')) {
                $cookieName = [string]$item['name']
                $cookieValue = [string]$item['value']
                if ($cookieName -and $cookieValue -and @('ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT') -contains $cookieName.ToUpperInvariant()) {
                    $candidates[$cookieName.ToUpperInvariant()] = $cookieValue.Trim()
                    continue
                }
            }

            $nestedCookie = Get-EstsAuthCookieFromSource -CookieSource $item
            if (-not [string]::IsNullOrWhiteSpace($nestedCookie) -and -not $candidates.Contains('ESTSAUTH')) {
                $candidates['ESTSAUTH'] = $nestedCookie
            }
        }

        foreach ($cookieName in @('ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT')) {
            if ($candidates.Contains($cookieName)) {
                return [string]$candidates[$cookieName]
            }
        }
    }

    return $null
}

function Resolve-EstsAuthCookie {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request
    )

    $directCookie = Get-RequestValue -Body $Body -Request $Request -Names @('estsAuth', 'estsAuthCookie')
    if (-not [string]::IsNullOrWhiteSpace($directCookie)) {
        $parsedDirectCookie = Get-EstsAuthCookieFromSource -CookieSource $directCookie
        if (-not [string]::IsNullOrWhiteSpace($parsedDirectCookie)) {
            return $parsedDirectCookie
        }
    }

    $cookieSource = Get-BodyValue -Body $Body -Names @('cookies', 'cookieExport', 'cookieJson', 'cookieData', 'browserCookies', 'tokens')
    if ($null -ne $cookieSource) {
        $parsedCookie = Get-EstsAuthCookieFromSource -CookieSource $cookieSource
        if (-not [string]::IsNullOrWhiteSpace($parsedCookie)) {
            return $parsedCookie
        }
    }

    $queryCookie = Get-RequestValue -Body $Body -Request $Request -Names @('cookies', 'cookieExport', 'cookieJson', 'cookieData', 'browserCookies', 'tokens')
    if (-not [string]::IsNullOrWhiteSpace($queryCookie)) {
        return Get-EstsAuthCookieFromSource -CookieSource $queryCookie
    }

    return $null
}

function Get-RequiredSetting {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw [System.ArgumentException]::new("Missing required setting '$Name'.")
    }

    return $value
}

function New-DefaultPasskeyDisplayName {
    $randomSuffix = Get-Random -Minimum 1000 -Maximum 10000
    return "pk$randomSuffix"
}

function Get-DefaultPasskeyUserAgent {
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
}

function Get-DefaultPasskeyRedirectUri {
    return 'https://mysignins.microsoft.com'
}

function Normalize-PasskeyUserAgent {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$UserAgent
    )

    $candidate = ''
    if ($null -ne $UserAgent) {
        $candidate = [string]$UserAgent
    }

    $candidate = $candidate.Replace([string][char]0, '')
    $candidate = $candidate.Replace("`r", ' ')
    $candidate = $candidate.Replace("`n", ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return Get-DefaultPasskeyUserAgent
    }

    return $candidate
}

function Resolve-RequestUserAgent {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request
    )

    $requestUserAgent = Get-RequestValue -Body $Body -Request $Request -Names @('userAgent', 'useragent')
    return Normalize-PasskeyUserAgent -UserAgent $requestUserAgent
}

function Normalize-PasskeyRedirectUri {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$RedirectUri
    )

    $candidate = ''
    if ($null -ne $RedirectUri) {
        $candidate = [string]$RedirectUri
    }

    $candidate = $candidate.Replace([string][char]0, '')
    $candidate = $candidate.Replace("`r", ' ')
    $candidate = $candidate.Replace("`n", ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return Get-DefaultPasskeyRedirectUri
    }

    $parsedUri = $null
    if (-not [System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$parsedUri)) {
        throw [System.ArgumentException]::new("The redirectUri value '$candidate' is not a valid absolute URI.")
    }

    if ($parsedUri.Scheme -notin @('http', 'https')) {
        throw [System.ArgumentException]::new("The redirectUri value '$candidate' must use http or https.")
    }

    if (-not [string]::IsNullOrWhiteSpace($parsedUri.Query) -or -not [string]::IsNullOrWhiteSpace($parsedUri.Fragment)) {
        throw [System.ArgumentException]::new("The redirectUri value '$candidate' must not include a query string or fragment.")
    }

    return $candidate
}

function Resolve-RequestRedirectUri {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request
    )

    $requestRedirectUri = Get-RequestValue -Body $Body -Request $Request -Names @('redirectUri', 'redirecturi')
    return Normalize-PasskeyRedirectUri -RedirectUri $requestRedirectUri
}

function Get-PasskeyFunctionConfiguration {
    $keyVaultAccessToken = [Environment]::GetEnvironmentVariable('PASSKEY_KEYVAULT_ACCESS_TOKEN')

    return [ordered]@{
        TenantId = Get-RequiredSetting -Name 'PASSKEY_TENANT_ID'
        KeyVaultName = Get-RequiredSetting -Name 'PASSKEY_KEYVAULT_NAME'
        ManagedIdentityClientId = [Environment]::GetEnvironmentVariable('PASSKEY_MANAGED_IDENTITY_CLIENT_ID')
        KeyVaultAccessToken = $keyVaultAccessToken
    }
}

function Get-OktaFunctionConfiguration {
    $keyVaultAccessToken = [Environment]::GetEnvironmentVariable('PASSKEY_KEYVAULT_ACCESS_TOKEN')
    $oktaDomain = [Environment]::GetEnvironmentVariable('PASSKEY_OKTA_DOMAIN')

    return [ordered]@{
        KeyVaultName = Get-RequiredSetting -Name 'PASSKEY_KEYVAULT_NAME'
        ManagedIdentityClientId = [Environment]::GetEnvironmentVariable('PASSKEY_MANAGED_IDENTITY_CLIENT_ID')
        KeyVaultAccessToken = $keyVaultAccessToken
        OktaDomain = $oktaDomain
    }
}

function Resolve-OktaDomain {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request
    )

    $domain = Get-RequestValue -Body $Body -Request $Request -Names @('oktaDomain', 'domain')
    if ([string]::IsNullOrWhiteSpace($domain)) {
        $domain = [Environment]::GetEnvironmentVariable('PASSKEY_OKTA_DOMAIN')
    }

    if ([string]::IsNullOrWhiteSpace($domain)) {
        throw [System.ArgumentException]::new("Missing required Okta domain. Set 'PASSKEY_OKTA_DOMAIN' or provide 'oktaDomain'.")
    }

    return $domain.Trim()
}

function Resolve-OktaAccessToken {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        $Request
    )

    $token = Get-RequestValue -Body $Body -Request $Request -Names @('accessToken', 'oktaAccessToken')
    if ([string]::IsNullOrWhiteSpace($token) -and $Request.Headers) {
        $authorization = $null
        if ($Request.Headers -is [System.Collections.IDictionary]) {
            if ($Request.Headers.ContainsKey('Authorization')) {
                $authorization = [string]$Request.Headers['Authorization']
            }
        } else {
            $property = $Request.Headers.PSObject.Properties['Authorization']
            if ($property) {
                $authorization = [string]$property.Value
            }
        }

        if ($authorization -and $authorization -match '^(?i)Bearer\s+(.+)$') {
            $token = $Matches[1].Trim()
        }
    }

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw [System.ArgumentException]::new("Missing Okta user access token. Provide 'accessToken' or a Bearer Authorization header.")
    }

    return $token
}

function Get-ManagedIdentityAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [Parameter()]
        [string]$ClientId
    )

    $identityEndpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')
    $identityHeader = [Environment]::GetEnvironmentVariable('IDENTITY_HEADER')
    if (-not [string]::IsNullOrWhiteSpace($identityEndpoint) -and -not [string]::IsNullOrWhiteSpace($identityHeader)) {
        $uri = "${identityEndpoint}?resource=$([uri]::EscapeDataString($resource))&api-version=2019-08-01"
        if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            $uri += "&client_id=$([uri]::EscapeDataString($clientId))"
        }

        $tokenResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $identityHeader }
        if (-not [string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
            return [string]$tokenResponse.access_token
        }
    }

    $msiEndpoint = [Environment]::GetEnvironmentVariable('MSI_ENDPOINT')
    $msiSecret = [Environment]::GetEnvironmentVariable('MSI_SECRET')
    if (-not [string]::IsNullOrWhiteSpace($msiEndpoint) -and -not [string]::IsNullOrWhiteSpace($msiSecret)) {
        $uri = "${msiEndpoint}?resource=$([uri]::EscapeDataString($resource))&api-version=2017-09-01"
        if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            $uri += "&clientid=$([uri]::EscapeDataString($clientId))"
        }

        $tokenResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Secret = $msiSecret }
        if (-not [string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
            return [string]$tokenResponse.access_token
        }
    }

    return $null
}

function Get-KeyVaultAccessToken {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Configuration.KeyVaultAccessToken)) {
        return [string]$Configuration.KeyVaultAccessToken
    }

    $token = Get-ManagedIdentityAccessToken -Resource 'https://vault.azure.net' -ClientId ([string]$Configuration.ManagedIdentityClientId)
    if (-not [string]::IsNullOrWhiteSpace($token)) {
        return $token
    }

    throw "Unable to acquire a Key Vault access token. Set PASSKEY_KEYVAULT_ACCESS_TOKEN for local development or run in Azure with managed identity."
}

function Get-StorageAccessToken {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    $token = Get-ManagedIdentityAccessToken -Resource 'https://storage.azure.com/' -ClientId ([string]$Configuration.ManagedIdentityClientId)
    if (-not [string]::IsNullOrWhiteSpace($token)) {
        return $token
    }

    throw "Unable to acquire a Storage access token. Run in Azure with managed identity or configure AzureWebJobsStorage with a supported identity."
}

function Get-StorageBlobServiceUri {
    $blobServiceUri = [Environment]::GetEnvironmentVariable('AzureWebJobsStorage__blobServiceUri')
    if ([string]::IsNullOrWhiteSpace($blobServiceUri)) {
        throw [System.ArgumentException]::new("Missing required setting 'AzureWebJobsStorage__blobServiceUri'.")
    }

    return $blobServiceUri.TrimEnd('/')
}

function Get-RegistrationStatusContainerName {
    $containerName = [Environment]::GetEnvironmentVariable('PASSKEY_REGISTRATION_STATUS_CONTAINER_NAME')
    if ([string]::IsNullOrWhiteSpace($containerName)) {
        return 'passkey-registration-status'
    }

    return $containerName.Trim().ToLowerInvariant()
}

function Get-PostRegistrationLoginDelaySeconds {
    $rawValue = [Environment]::GetEnvironmentVariable('PASSKEY_POST_REGISTRATION_LOGIN_DELAY_SECONDS')
    $delaySeconds = 10
    if (-not [string]::IsNullOrWhiteSpace($rawValue)) {
        [void][int]::TryParse($rawValue, [ref]$delaySeconds)
    }

    if ($delaySeconds -lt 0) {
        return 0
    }

    return $delaySeconds
}

function Get-PostRegistrationLoginHint {
    return [ordered]@{
        delaySeconds = Get-PostRegistrationLoginDelaySeconds
        note = 'Newly registered passkeys can take a few seconds before login succeeds. If you automate login immediately after registration, wait briefly and retry once.'
    }
}

function Get-RegistrationStatusBlobUri {
    param(
        [Parameter(Mandatory)]
        [string]$RequestId
    )

    $blobServiceUri = Get-StorageBlobServiceUri
    $containerName = Get-RegistrationStatusContainerName
    $blobName = [uri]::EscapeDataString("$RequestId.json")
    return "$blobServiceUri/$containerName/$blobName"
}

function Ensure-RegistrationStatusContainer {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    $statusContainerCache = Get-Variable -Name PasskeyStatusContainerEnsured -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $statusContainerCache) {
        $script:PasskeyStatusContainerEnsured = @{}
    }

    $containerName = Get-RegistrationStatusContainerName
    if ($script:PasskeyStatusContainerEnsured.ContainsKey($containerName)) {
        return
    }

    $storageToken = Get-StorageAccessToken -Configuration $Configuration
    $containerUri = "$(Get-StorageBlobServiceUri)/${containerName}?restype=container"
    $headers = @{
        Authorization = "Bearer $storageToken"
        'x-ms-version' = '2023-11-03'
        'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R')
    }

    try {
        Invoke-WebRequest -Method PUT -Uri $containerUri -Headers $headers -ContentType 'application/octet-stream' | Out-Null
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -ne 409) {
            throw
        }
    }

    $script:PasskeyStatusContainerEnsured[$containerName] = $true
}

function Set-RegistrationStatus {
    param(
        [Parameter(Mandatory)]
        [string]$RequestId,

        [Parameter(Mandatory)]
        [hashtable]$Status,

        [Parameter()]
        [hashtable]$Configuration
    )

    if ($null -eq $Configuration) {
        $Configuration = Get-PasskeyFunctionConfiguration
    }
    Ensure-RegistrationStatusContainer -Configuration $Configuration

    $status.updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    if (-not $Status.ContainsKey('requestId') -or [string]::IsNullOrWhiteSpace([string]$Status.requestId)) {
        $status.requestId = $RequestId
    }
    if (-not $Status.ContainsKey('loginPropagation')) {
        $status.loginPropagation = Get-PostRegistrationLoginHint
    }

    $storageToken = Get-StorageAccessToken -Configuration $Configuration
    $blobUri = Get-RegistrationStatusBlobUri -RequestId $RequestId
    $body = $status | ConvertTo-Json -Depth 30
    $headers = @{
        Authorization = "Bearer $storageToken"
        'x-ms-version' = '2023-11-03'
        'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R')
        'x-ms-blob-type' = 'BlockBlob'
    }

    Invoke-WebRequest -Method PUT -Uri $blobUri -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $body | Out-Null
}

function Get-RegistrationStatus {
    param(
        [Parameter(Mandatory)]
        [string]$RequestId,

        [Parameter()]
        [hashtable]$Configuration
    )

    if ($null -eq $Configuration) {
        $Configuration = Get-PasskeyFunctionConfiguration
    }
    $storageToken = Get-StorageAccessToken -Configuration $Configuration
    $blobUri = Get-RegistrationStatusBlobUri -RequestId $RequestId
    $headers = @{
        Authorization = "Bearer $storageToken"
        'x-ms-version' = '2023-11-03'
        'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R')
    }

    try {
        $response = Invoke-WebRequest -Method GET -Uri $blobUri -Headers $headers
        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            return $null
        }

        return $response.Content | ConvertFrom-Json -AsHashtable -Depth 30
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 404) {
            return $null
        }

        throw
    }
}

function Get-RegistrationStatusUrl {
    param(
        [Parameter(Mandatory)]
        $Request,

        [Parameter(Mandatory)]
        [string]$RequestId,

        [Parameter()]
        [ValidateSet('entra', 'okta')]
        [string]$Provider = 'entra'
    )

    $relativePath = "/api/$Provider/passkeys/register/status/$RequestId"
    $code = $null
    if ($null -ne $Request.Query) {
        if ($Request.Query -is [System.Collections.IDictionary]) {
            if ($Request.Query.ContainsKey('code')) {
                $code = [string]$Request.Query['code']
            }
        } else {
            $property = $Request.Query.PSObject.Properties['code']
            if ($property) {
                $code = [string]$property.Value
            }
        }
    }

    if ($Request.Url) {
        $requestUri = if ($Request.Url -is [uri]) { $Request.Url } else { [uri][string]$Request.Url }
        $baseUrl = $requestUri.GetLeftPart([System.UriPartial]::Authority)
        $statusUrl = "$baseUrl$relativePath"
        if (-not [string]::IsNullOrWhiteSpace($code)) {
            $statusUrl += "?code=$([uri]::EscapeDataString($code))"
        }
        return $statusUrl
    }

    if (-not [string]::IsNullOrWhiteSpace($code)) {
        return "$relativePath?code=$([uri]::EscapeDataString($code))"
    }

    return $relativePath
}

function New-TempOutputPath {
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$AuthMethod
    )

    $safeUser = ($UserPrincipalName.Split('@')[0] -replace '[^0-9A-Za-z-]', '')
    if ([string]::IsNullOrWhiteSpace($safeUser)) {
        $safeUser = 'user'
    }

    $tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    return Join-Path $tempRoot "$safeUser-$AuthMethod-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

function Invoke-PasskeyRegistrationScript {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [hashtable]$Parameters
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Script not found: $ScriptPath"
    }

    $outputPath = [string]$Parameters.OutputPath
    try {
        & $ScriptPath @Parameters | Out-Null
        if (-not (Test-Path -LiteralPath $outputPath)) {
            throw "The registration script did not create the expected output file: $outputPath"
        }

        return Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -AsHashtable
    } finally {
        if ($outputPath -and (Test-Path -LiteralPath $outputPath)) {
            Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-EstsAuthPasskeyRegistration {
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$EstsAuthCookie,

        [Parameter()]
        [string]$DisplayName,

        [Parameter()]
        [string]$KeyVaultKeyName,

        [Parameter()]
        [string]$UserAgent,

        [Parameter()]
        [string]$RedirectUri
    )

    $configuration = Get-PasskeyFunctionConfiguration
    $keyVaultAccessToken = Get-KeyVaultAccessToken -Configuration $configuration
    $scriptPath = Join-Path $PSScriptRoot 'passkey-assets\scripts\entra\reference\Register-EntraKeyVaultPasskeyViaEstsAuth.ps1'
    $outputPath = New-TempOutputPath -UserPrincipalName $UserPrincipalName -AuthMethod 'estsauth'

    $scriptParameters = @{
        ESTSAuthCookie = $EstsAuthCookie
        TenantId = $configuration.TenantId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = $keyVaultAccessToken
        OutputPath = $outputPath
    }

    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $scriptParameters.PasskeyDisplayName = $DisplayName
    }

    if (-not [string]::IsNullOrWhiteSpace($KeyVaultKeyName)) {
        $scriptParameters.KeyVaultKeyName = $KeyVaultKeyName
    }

    if (-not [string]::IsNullOrWhiteSpace($UserAgent)) {
        $scriptParameters.UserAgent = (Normalize-PasskeyUserAgent -UserAgent $UserAgent)
    }

    if (-not [string]::IsNullOrWhiteSpace($RedirectUri)) {
        $scriptParameters.RedirectUri = (Normalize-PasskeyRedirectUri -RedirectUri $RedirectUri)
    }

    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $scriptParameters
    if ([string]::Compare([string]$credential.userName, $UserPrincipalName, $true) -ne 0) {
        throw [System.InvalidOperationException]::new("The ESTSAUTH cookie resolved to '$($credential.userName)', which does not match the requested user '$UserPrincipalName'.")
    }

    return [ordered]@{
        Configuration = $configuration
        Credential = $credential
    }
}

function Get-CredentialPayload {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Body
    )

    if ($Body.ContainsKey('credential')) {
        $credential = $Body['credential']
        if ($credential -is [System.Collections.IDictionary]) {
            return [hashtable]$credential
        }

        return ($credential | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable)
    }

    $payload = [ordered]@{}
    foreach ($entry in $Body.GetEnumerator()) {
        if ($entry.Key -in @('authUrl', 'keyVaultName', 'keyVaultKeyName', 'userAgent', 'useragent', 'redirectUri', 'redirecturi')) {
            continue
        }

        $payload[$entry.Key] = $entry.Value
    }

    return [hashtable]$payload
}

function Invoke-PasskeyLoginScript {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [object]$Credential,

        [Parameter()]
        [hashtable]$Parameters = @{}
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Script not found: $ScriptPath"
    }

    $userPrincipalName = [string]($Credential.userName ?? $Credential.username ?? $Credential.userPrincipalName ?? 'user')
    $credentialPath = New-TempOutputPath -UserPrincipalName $userPrincipalName -AuthMethod 'login'

    try {
        $Credential | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $credentialPath -Encoding UTF8
        Remove-Variable -Name ESTSAUTH -Scope Global -ErrorAction SilentlyContinue

        $loginParameters = @{
            KeyFilePath = $credentialPath
            PassThru    = $true
        } + $Parameters

        $result = & $ScriptPath @loginParameters
        $estsAuthCookie = $null
        $estsVariable = Get-Variable -Name ESTSAUTH -Scope Global -ErrorAction SilentlyContinue
        if ($estsVariable) {
            $estsAuthCookie = [string]$estsVariable.Value
        }

        return [ordered]@{
            Result         = $result
            ESTSAuthCookie = $estsAuthCookie
        }
    } finally {
        if (Test-Path -LiteralPath $credentialPath) {
            Remove-Item -LiteralPath $credentialPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-JsonHttpResponse {
    param(
        [Parameter(Mandatory)]
        [HttpStatusCode]$StatusCode,

        [Parameter(Mandatory)]
        $Body
    )

    $response = @{
        StatusCode = $StatusCode
        Headers = @{
            'Content-Type' = 'application/json'
        }
        Body = ($Body | ConvertTo-Json -Depth 20)
    }

    if ('HttpResponseContext' -as [type]) {
        return [HttpResponseContext]$response
    }

    return [pscustomobject]$response
}
