[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$DisplayName = 'Software Passkey',

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$PowerShellFunctionUrl,

    [Parameter()]
    [string]$PythonFunctionUrl,

    [Parameter()]
    [string]$PowerShellBaseUrl,

    [Parameter()]
    [string]$PythonBaseUrl,

    [Parameter()]
    [string]$PowerShellFunctionKey,

    [Parameter()]
    [string]$PythonFunctionKey,

    [Parameter()]
    [string]$CommonFunctionKey,

    [Parameter()]
    [string]$EstsAuth,

    [Parameter()]
    [string]$EstsAuthEnvVar = 'PASSKEY_ESTSAUTH',

    [Parameter()]
    [string]$CookieExportPath,

    [Parameter()]
    [string]$CookieExportJson,

    [Parameter()]
    [switch]$PromptForEstsAuth,

    [Parameter()]
    [ValidateSet('powershell', 'python', 'both')]
    [string]$Target = 'both',

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function ConvertTo-PlainTextSecret {
    param(
        [Parameter(Mandatory)]
        [object]$Value
    )

    if ($Value -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $Value).Password
    }

    return [string]$Value
}

function Resolve-EndpointUrl {
    param(
        [Parameter()]
        [string]$ExplicitUrl,

        [Parameter()]
        [string]$BaseUrl,

        [Parameter()]
        [string]$FunctionKey
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitUrl)) {
        return $ExplicitUrl
    }

    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        return $null
    }

    $trimmedBase = $BaseUrl.TrimEnd('/')
    $url = "$trimmedBase/api/passkeys/register/estsauth/queue"
    if (-not [string]::IsNullOrWhiteSpace($FunctionKey)) {
        $separator = if ($url.Contains('?')) { '&' } else { '?' }
        $url = "$url${separator}code=$([uri]::EscapeDataString($FunctionKey))"
    }

    return $url
}

function Resolve-CookieExportPayload {
    param(
        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Json
    )

    $raw = $null
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Cookie export file not found: $Path"
        }

        $raw = Get-Content -LiteralPath $Path -Raw
    } elseif (-not [string]::IsNullOrWhiteSpace($Json)) {
        $raw = $Json
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    try {
        return $raw | ConvertFrom-Json -AsHashtable -Depth 50
    } catch {
        try {
            return $raw | ConvertFrom-Json -Depth 50
        } catch {
            return $raw
        }
    }
}

function Resolve-EstsAuthValue {
    param(
        [Parameter()]
        [string]$DirectValue,

        [Parameter(Mandatory)]
        [string]$EnvironmentVariableName,

        [Parameter()]
        [switch]$Prompt
    )

    if (-not [string]::IsNullOrWhiteSpace($DirectValue)) {
        return $DirectValue
    }

    $envValue = [Environment]::GetEnvironmentVariable($EnvironmentVariableName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        return $envValue
    }

    if ($Prompt) {
        return ConvertTo-PlainTextSecret -Value (Read-Host "Enter ESTSAUTH" -AsSecureString)
    }

    return $null
}

function Invoke-QueueRegistrationRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [hashtable]$Payload
    )

    $jsonBody = $Payload | ConvertTo-Json -Depth 50
    try {
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $jsonBody -ContentType 'application/json'
        $parsed = if ([string]::IsNullOrWhiteSpace($response.Content)) { @{} } else { $response.Content | ConvertFrom-Json -AsHashtable }
        $statusUrl = [string]($parsed.statusUrl ?? '')
        if (-not [string]::IsNullOrWhiteSpace($statusUrl) -and $statusUrl.StartsWith('/')) {
            $responseUri = [uri]$Url
            $statusUrl = "$($responseUri.Scheme)://$($responseUri.Authority)$statusUrl"
        }
        return [ordered]@{
            target            = $Name
            attempted         = $true
            endpoint          = $Url
            httpStatus        = [int]$response.StatusCode
            success           = [bool]($parsed.success)
            queued            = [bool]($parsed.queued)
            requestId         = [string]($parsed.requestId ?? '')
            queueName         = [string]($parsed.queueName ?? '')
            userPrincipalName = [string]($parsed.userPrincipalName ?? '')
            statusUrl         = $statusUrl
            error             = $null
        }
    } catch {
        $statusCode = $null
        $responseBody = $null
        if ($_.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
            $responseBody = [string]$_.ErrorDetails.Message
        }
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if (-not $responseBody) {
                try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $reader.Dispose()
                } catch {
                }
            }
        }

        $errorMessage = $_.Exception.Message
        if ($responseBody) {
            try {
                $parsedError = $responseBody | ConvertFrom-Json -AsHashtable
                if ($parsedError.error) {
                    $errorMessage = [string]$parsedError.error
                }
            } catch {
            }
        }

        return [ordered]@{
            target            = $Name
            attempted         = $true
            endpoint          = $Url
            httpStatus        = $statusCode
            success           = $false
            queued            = $false
            requestId         = $null
            queueName         = $null
            userPrincipalName = $UserPrincipalName
            statusUrl         = $null
            error             = $errorMessage
        }
    }
}

$cookieExportPayload = Resolve-CookieExportPayload -Path $CookieExportPath -Json $CookieExportJson
$estsAuthValue = $null
if ($null -eq $cookieExportPayload) {
    $estsAuthValue = Resolve-EstsAuthValue -DirectValue $EstsAuth -EnvironmentVariableName $EstsAuthEnvVar -Prompt:$PromptForEstsAuth
    if ([string]::IsNullOrWhiteSpace($estsAuthValue)) {
        throw "Provide -EstsAuth, set $EstsAuthEnvVar, use -PromptForEstsAuth, or provide -CookieExportPath/-CookieExportJson."
    }
}

$payload = [ordered]@{
    userPrincipalName = $UserPrincipalName
    displayName = $DisplayName
}
if (-not [string]::IsNullOrWhiteSpace($KeyVaultKeyName)) {
    $payload.keyVaultKeyName = $KeyVaultKeyName
}
if ($null -ne $cookieExportPayload) {
    $payload.cookieExport = $cookieExportPayload
} else {
    $payload.estsAuth = $estsAuthValue
}

$resolvedPowerShellUrl = Resolve-EndpointUrl `
    -ExplicitUrl $PowerShellFunctionUrl `
    -BaseUrl $PowerShellBaseUrl `
    -FunctionKey ($PowerShellFunctionKey ?? $CommonFunctionKey)
$resolvedPythonUrl = Resolve-EndpointUrl `
    -ExplicitUrl $PythonFunctionUrl `
    -BaseUrl $PythonBaseUrl `
    -FunctionKey ($PythonFunctionKey ?? $CommonFunctionKey)

$results = @()
if ($Target -in @('powershell', 'both')) {
    if ([string]::IsNullOrWhiteSpace($resolvedPowerShellUrl)) {
        throw 'PowerShell target selected, but no PowerShell function URL or base URL was provided.'
    }

    $results += Invoke-QueueRegistrationRequest -Name 'powershell' -Url $resolvedPowerShellUrl -Payload $payload
}

if ($Target -in @('python', 'both')) {
    if ([string]::IsNullOrWhiteSpace($resolvedPythonUrl)) {
        throw 'Python target selected, but no Python function URL or base URL was provided.'
    }

    $results += Invoke-QueueRegistrationRequest -Name 'python' -Url $resolvedPythonUrl -Payload $payload
}

$summary = [ordered]@{
    submittedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    userPrincipalName = $UserPrincipalName
    usedCookieExport = $null -ne $cookieExportPayload
    targets = $results
}

if ($PassThru) {
    Write-Output ([pscustomobject]$summary)
} else {
    $summary | ConvertTo-Json -Depth 20
}
