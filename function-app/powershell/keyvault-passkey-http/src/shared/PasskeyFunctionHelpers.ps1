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

        if ($Request.Query.$name -and -not [string]::IsNullOrWhiteSpace([string]$Request.Query.$name)) {
            return [string]$Request.Query.$name
        }
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

function Get-PasskeyFunctionConfiguration {
    $keyVaultAccessToken = [Environment]::GetEnvironmentVariable('PASSKEY_KEYVAULT_ACCESS_TOKEN')

    return [ordered]@{
        TenantId = Get-RequiredSetting -Name 'PASSKEY_TENANT_ID'
        KeyVaultName = Get-RequiredSetting -Name 'PASSKEY_KEYVAULT_NAME'
        ManagedIdentityClientId = [Environment]::GetEnvironmentVariable('PASSKEY_MANAGED_IDENTITY_CLIENT_ID')
        KeyVaultAccessToken = $keyVaultAccessToken
    }
}

function Get-KeyVaultAccessToken {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Configuration.KeyVaultAccessToken)) {
        return [string]$Configuration.KeyVaultAccessToken
    }

    $resource = 'https://vault.azure.net'
    $clientId = [string]$Configuration.ManagedIdentityClientId

    $identityEndpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')
    $identityHeader = [Environment]::GetEnvironmentVariable('IDENTITY_HEADER')
    if (-not [string]::IsNullOrWhiteSpace($identityEndpoint) -and -not [string]::IsNullOrWhiteSpace($identityHeader)) {
        $uri = "$identityEndpoint?resource=$([uri]::EscapeDataString($resource))&api-version=2019-08-01"
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
        $uri = "$msiEndpoint?resource=$([uri]::EscapeDataString($resource))&api-version=2017-09-01"
        if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            $uri += "&clientid=$([uri]::EscapeDataString($clientId))"
        }

        $tokenResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Secret = $msiSecret }
        if (-not [string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
            return [string]$tokenResponse.access_token
        }
    }

    throw "Unable to acquire a Key Vault access token. Set PASSKEY_KEYVAULT_ACCESS_TOKEN for local development or run in Azure with managed identity."
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

    return Join-Path $env:TEMP "$safeUser-$AuthMethod-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
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
        if ($entry.Key -in @('authUrl', 'keyVaultName', 'keyVaultKeyName')) {
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
