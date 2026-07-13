[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [object]$Tap,

    [Parameter()]
    [string]$TapEnvVar = 'PASSKEY_TAP',

    [Parameter(Mandatory)]
    [string]$PowerShellBaseUrl,

    [Parameter(Mandatory)]
    [string]$PythonBaseUrl,

    [Parameter(Mandatory)]
    [string]$PowerShellFunctionKey,

    [Parameter(Mandatory)]
    [string]$PythonFunctionKey,

    [Parameter()]
    [string]$DisplayName = 'Queue Validation Passkey',

    [Parameter()]
    [string]$OutputDirectory,

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

function Resolve-TapValue {
    param(
        [Parameter()]
        [object]$ProvidedTap,

        [Parameter(Mandatory)]
        [string]$EnvironmentVariableName
    )

    if ($null -ne $ProvidedTap) {
        $plainText = ConvertTo-PlainTextSecret -Value $ProvidedTap
        if (-not [string]::IsNullOrWhiteSpace($plainText)) {
            return $plainText
        }
    }

    $envValue = [Environment]::GetEnvironmentVariable($EnvironmentVariableName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        return $envValue
    }

    throw "Provide -Tap or set $EnvironmentVariableName."
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tapValue = Resolve-TapValue -ProvidedTap $Tap -EnvironmentVariableName $TapEnvVar

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "passkey-live-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$smokeScript = Join-Path $PSScriptRoot 'Invoke-EntraPasskeySmokeTest.ps1'
$queueScript = Join-Path $PSScriptRoot 'Invoke-EntraQueuePasskeyRegistration.ps1'

$powerShellRegisterUrl = "$($PowerShellBaseUrl.TrimEnd('/'))/api/entra/passkeys/register/tap?code=$([uri]::EscapeDataString($PowerShellFunctionKey))"
$pythonRegisterUrl = "$($PythonBaseUrl.TrimEnd('/'))/api/entra/passkeys/register/tap?code=$([uri]::EscapeDataString($PythonFunctionKey))"
$powerShellLoginUrl = "$($PowerShellBaseUrl.TrimEnd('/'))/api/entra/passkeys/login?code=$([uri]::EscapeDataString($PowerShellFunctionKey))"
$pythonLoginUrl = "$($PythonBaseUrl.TrimEnd('/'))/api/entra/passkeys/login?code=$([uri]::EscapeDataString($PythonFunctionKey))"

$smokeOutputDirectory = Join-Path $OutputDirectory 'smoke'
$queueOutputPath = Join-Path $OutputDirectory 'queue-summary.json'

$smokeResult = & $smokeScript `
    -UserPrincipalName $UserPrincipalName `
    -Tap $tapValue `
    -KeyVaultName $KeyVaultName `
    -PowerShellFunctionUrl $powerShellRegisterUrl `
    -PythonFunctionUrl $pythonRegisterUrl `
    -PowerShellFunctionLoginUrl $powerShellLoginUrl `
    -PythonFunctionLoginUrl $pythonLoginUrl `
    -SkipDirectRegistration `
    -SkipPowerShellLogin `
    -SkipPythonLogin `
    -OutputDirectory $smokeOutputDirectory `
    -PassThru

if (-not $smokeResult.estsAuthCookie) {
    throw 'No ESTSAUTH cookie was captured from the live function login flow.'
}

$queueResult = & $queueScript `
    -UserPrincipalName $UserPrincipalName `
    -DisplayName $DisplayName `
    -PowerShellBaseUrl $PowerShellBaseUrl `
    -PythonBaseUrl $PythonBaseUrl `
    -PowerShellFunctionKey $PowerShellFunctionKey `
    -PythonFunctionKey $PythonFunctionKey `
    -EstsAuth $smokeResult.estsAuthCookie `
    -Target both `
    -PassThru

$queueResult | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $queueOutputPath -Encoding UTF8

$summary = [ordered]@{
    outputDirectory = $OutputDirectory
    smoke = [ordered]@{
        preferredCredentialPath = $smokeResult.preferredCredentialPath
        surfaceMatrix = $smokeResult.surfaceMatrix
        powerShellFunctionLoginResult = if ($smokeResult.powerShellFunctionLoginResult) {
            [ordered]@{
                success = [bool]$smokeResult.powerShellFunctionLoginResult.success
                cookieType = $smokeResult.powerShellFunctionLoginResult.cookieType
                userPrincipalName = $smokeResult.powerShellFunctionLoginResult.userPrincipalName
            }
        } else {
            $null
        }
        pythonFunctionLoginResult = if ($smokeResult.pythonFunctionLoginResult) {
            [ordered]@{
                success = [bool]$smokeResult.pythonFunctionLoginResult.success
                cookieType = $smokeResult.pythonFunctionLoginResult.cookieType
                userPrincipalName = $smokeResult.pythonFunctionLoginResult.userPrincipalName
            }
        } else {
            $null
        }
    }
    queue = $queueResult
}

if ($PassThru) {
    Write-Output ([pscustomobject]$summary)
} else {
    $summary | ConvertTo-Json -Depth 20
}
