[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [object]$Tap,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$TenantId = '847b5907-ca15-40f4-b171-eb18619dbfab',

    [Parameter()]
    [string]$OutputDirectory,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [string]$PowerShellFunctionUrl,

    [Parameter()]
    [string]$PythonFunctionUrl,

    [Parameter()]
    [string]$PythonCommand = 'python',

    [Parameter()]
    [switch]$SkipDirectRegistration,

    [Parameter()]
    [switch]$SkipPowerShellLogin,

    [Parameter()]
    [switch]$SkipPythonLogin,

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

function Save-CredentialFile {
    param(
        [Parameter(Mandatory)]
        [object]$CredentialObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $CredentialObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
    return $Path
}

function Invoke-TapFunctionRegistration {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $body = @{
        userPrincipalName = $UserPrincipalName
        tap               = $tapPlainText
        displayName       = $DisplayName
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $Uri -Method POST -Body $body -ContentType 'application/json'
    if (-not $response.success) {
        throw "Function registration failed for $Uri"
    }

    return $response.credential
}

function Invoke-PythonLogin {
    param(
        [Parameter(Mandatory)]
        [string]$CredentialPath
    )

    $pythonLoginScript = Join-Path $repoRoot 'python\samples\passkey-login\login_keyvault_passkey.py'
    $output = & $PythonCommand $pythonLoginScript --credential-path $CredentialPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python login failed.`n$($output -join [Environment]::NewLine)"
    }

    return ($output | Select-Object -Last 1) | ConvertFrom-Json
}

$tapPlainText = ConvertTo-PlainTextSecret -Value $Tap
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $env:TEMP "passkey-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$directCredentialPath = Join-Path $OutputDirectory 'direct-registration.json'
$powerShellFunctionCredentialPath = Join-Path $OutputDirectory 'powershell-function-registration.json'
$pythonFunctionCredentialPath = Join-Path $OutputDirectory 'python-function-registration.json'

$registrationResults = [ordered]@{}

if (-not $SkipDirectRegistration) {
    $registrationScript = Join-Path $repoRoot 'powershell\scripts\Register-KeyVaultPasskey.ps1'
    $registrationParams = @{
        TAP               = $tapPlainText
        UserPrincipalName = $UserPrincipalName
        TenantId          = $TenantId
        KeyVaultName      = $KeyVaultName
        OutputPath        = $directCredentialPath
    }
    if ($KeyVaultAccessToken) {
        $registrationParams.KeyVaultAccessToken = $KeyVaultAccessToken
    }

    & $registrationScript @registrationParams | Out-Null
    $registrationResults.direct = $directCredentialPath
}

if ($PowerShellFunctionUrl) {
    $credential = Invoke-TapFunctionRegistration -Uri $PowerShellFunctionUrl -DisplayName 'PowerShell Function Smoke Test'
    Save-CredentialFile -CredentialObject $credential -Path $powerShellFunctionCredentialPath | Out-Null
    $registrationResults.powerShellFunction = $powerShellFunctionCredentialPath
}

if ($PythonFunctionUrl) {
    $credential = Invoke-TapFunctionRegistration -Uri $PythonFunctionUrl -DisplayName 'Python Function Smoke Test'
    Save-CredentialFile -CredentialObject $credential -Path $pythonFunctionCredentialPath | Out-Null
    $registrationResults.pythonFunction = $pythonFunctionCredentialPath
}

$preferredCredentialPath = @(
    $directCredentialPath,
    $powerShellFunctionCredentialPath,
    $pythonFunctionCredentialPath
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $preferredCredentialPath) {
    throw 'No credential file was produced. Provide at least one registration path to validate.'
}

$powerShellLoginResult = $null
if (-not $SkipPowerShellLogin) {
    $powerShellLoginScript = Join-Path $repoRoot 'powershell\scripts\reference\PasskeyLogin.ps1'
    $loginParams = @{
        KeyFilePath       = $preferredCredentialPath
        KeyVaultTenantId  = $TenantId
        PassThru          = $true
    }
    if ($KeyVaultAccessToken) {
        $loginParams.KeyVaultAccessToken = $KeyVaultAccessToken
    }

    $powerShellLoginResult = & $powerShellLoginScript @loginParams
}

$pythonLoginResult = $null
if (-not $SkipPythonLogin) {
    $pythonLoginResult = Invoke-PythonLogin -CredentialPath $preferredCredentialPath
}

$result = [PSCustomObject]@{
    outputDirectory          = $OutputDirectory
    preferredCredentialPath  = $preferredCredentialPath
    registrationResults      = [PSCustomObject]$registrationResults
    powerShellLoginResult    = $powerShellLoginResult
    pythonLoginResult        = $pythonLoginResult
}

if ($PassThru) {
    Write-Output $result
} else {
    $result | ConvertTo-Json -Depth 10
}
