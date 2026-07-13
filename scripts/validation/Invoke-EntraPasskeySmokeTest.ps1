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
    [string]$PowerShellFunctionLoginUrl,

    [Parameter()]
    [string]$PythonFunctionLoginUrl,

    [Parameter()]
    [string]$PythonCommand = 'python',

    [Parameter()]
    [ValidateSet('tap', 'estsauth')]
    [string]$PythonLocalRegistrationMode,

    [Parameter()]
    [string]$EstsAuthCookie,

    [Parameter()]
    [int]$PostRegistrationLoginDelaySeconds = 10,

    [Parameter()]
    [int]$PostRegistrationLoginRetryCount = 2,

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

function New-SurfaceResult {
    param(
        [Parameter(Mandatory)]
        [bool]$Implemented
    )

    return [ordered]@{
        implemented = $Implemented
        attempted   = $false
        success     = $null
        detail      = $null
    }
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

function Invoke-FunctionPasskeyLogin {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [object]$Credential
    )

    $body = @{
        credential = $Credential
    } | ConvertTo-Json -Depth 20

    return Invoke-RestMethod -Uri $Uri -Method POST -Body $body -ContentType 'application/json'
}

function Invoke-PythonLocalRegistration {
    param(
        [Parameter(Mandatory)]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Cookie
    )

    $pythonRegistrationScript = Join-Path $repoRoot 'python\samples\entra\register_entra_keyvault_passkey.py'
    $arguments = @(
        $pythonRegistrationScript,
        '--user-principal-name', $UserPrincipalName,
        '--tenant-id', $TenantId,
        '--keyvault-name', $KeyVaultName,
        '--output-path', $OutputPath
    )
    if ($KeyVaultAccessToken) {
        $arguments += @('--keyvault-access-token', $KeyVaultAccessToken)
    }

    if ($Mode -eq 'tap') {
        $arguments += @('tap', '--tap', $tapPlainText)
    } else {
        if (-not $Cookie) {
            throw 'Python ESTSAUTH registration requires -EstsAuthCookie or a prior login result.'
        }
        $arguments += @('estsauth', '--ests-auth', $Cookie)
    }

    $output = & $PythonCommand @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python registration failed.`n$($output -join [Environment]::NewLine)"
    }

    return ($output | Select-Object -Last 1) | ConvertFrom-Json
}

function Invoke-PythonLogin {
    param(
        [Parameter(Mandatory)]
        [string]$CredentialPath
    )

    $pythonLoginScript = Join-Path $repoRoot 'python\samples\entra\invoke_entra_passkey_login.py'
    $output = & $PythonCommand $pythonLoginScript --credential-path $CredentialPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python login failed.`n$($output -join [Environment]::NewLine)"
    }

    return ($output | Select-Object -Last 1) | ConvertFrom-Json
}

function Resolve-PreferredCredentialPath {
    param(
        [Parameter(Mandatory)]
        [string[]]$Paths
    )

    return $Paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter()]
        [int]$RetryCount = 1,

        [Parameter()]
        [int]$DelaySeconds = 0
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $Action
        } catch {
            if ($attempt -ge $RetryCount) {
                throw
            }

            Write-Verbose "$Label attempt $attempt failed: $($_.Exception.Message)"
            if ($DelaySeconds -gt 0) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
}

$tapPlainText = ConvertTo-PlainTextSecret -Value $Tap
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $env:TEMP "passkey-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$directCredentialPath = Join-Path $OutputDirectory 'direct-registration.json'
$pythonLocalCredentialPath = Join-Path $OutputDirectory 'python-local-registration.json'
$powerShellFunctionCredentialPath = Join-Path $OutputDirectory 'powershell-function-registration.json'
$pythonFunctionCredentialPath = Join-Path $OutputDirectory 'python-function-registration.json'

$registrationResults = [ordered]@{}
$surfaceMatrix = [ordered]@{
    powerShellLocalRegistration  = New-SurfaceResult -Implemented $true
    pythonLocalRegistration      = New-SurfaceResult -Implemented $true
    powerShellFunctionRegistration = New-SurfaceResult -Implemented $true
    pythonFunctionRegistration   = New-SurfaceResult -Implemented $true
    powerShellLocalLogin         = New-SurfaceResult -Implemented $true
    pythonLocalLogin             = New-SurfaceResult -Implemented $true
    powerShellFunctionLogin      = New-SurfaceResult -Implemented $true
    pythonFunctionLogin          = New-SurfaceResult -Implemented $true
}

if (-not $SkipDirectRegistration) {
    $surfaceMatrix.powerShellLocalRegistration.attempted = $true
    $registrationScript = Join-Path $repoRoot 'powershell\scripts\entra\Register-EntraKeyVaultPasskey.ps1'
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
    $surfaceMatrix.powerShellLocalRegistration.success = $true
    $surfaceMatrix.powerShellLocalRegistration.detail = $directCredentialPath
} else {
    $surfaceMatrix.powerShellLocalRegistration.detail = 'Skipped by request.'
}

if ($PythonLocalRegistrationMode -eq 'tap') {
    $surfaceMatrix.pythonLocalRegistration.attempted = $true
    $pythonRegistration = Invoke-PythonLocalRegistration -Mode $PythonLocalRegistrationMode -OutputPath $pythonLocalCredentialPath
    if (-not $pythonRegistration.success) {
        throw 'Python local registration reported failure.'
    }
    $registrationResults.pythonLocal = $pythonLocalCredentialPath
    $surfaceMatrix.pythonLocalRegistration.success = $true
    $surfaceMatrix.pythonLocalRegistration.detail = $pythonLocalCredentialPath
} elseif (-not $PythonLocalRegistrationMode) {
    $surfaceMatrix.pythonLocalRegistration.detail = 'Provide -PythonLocalRegistrationMode to validate the local Python registration wrapper.'
}

if ($PowerShellFunctionUrl) {
    $surfaceMatrix.powerShellFunctionRegistration.attempted = $true
    $credential = Invoke-TapFunctionRegistration -Uri $PowerShellFunctionUrl -DisplayName 'PowerShell Function Smoke Test'
    Save-CredentialFile -CredentialObject $credential -Path $powerShellFunctionCredentialPath | Out-Null
    $registrationResults.powerShellFunction = $powerShellFunctionCredentialPath
    $surfaceMatrix.powerShellFunctionRegistration.success = $true
    $surfaceMatrix.powerShellFunctionRegistration.detail = $powerShellFunctionCredentialPath
} else {
    $surfaceMatrix.powerShellFunctionRegistration.detail = 'No PowerShell function registration URL was supplied.'
}

if ($PythonFunctionUrl) {
    $surfaceMatrix.pythonFunctionRegistration.attempted = $true
    $credential = Invoke-TapFunctionRegistration -Uri $PythonFunctionUrl -DisplayName 'Python Function Smoke Test'
    Save-CredentialFile -CredentialObject $credential -Path $pythonFunctionCredentialPath | Out-Null
    $registrationResults.pythonFunction = $pythonFunctionCredentialPath
    $surfaceMatrix.pythonFunctionRegistration.success = $true
    $surfaceMatrix.pythonFunctionRegistration.detail = $pythonFunctionCredentialPath
} else {
    $surfaceMatrix.pythonFunctionRegistration.detail = 'No Python function registration URL was supplied.'
}

$preferredCredentialPath = Resolve-PreferredCredentialPath -Paths @(
    $directCredentialPath,
    $pythonLocalCredentialPath,
    $powerShellFunctionCredentialPath,
    $pythonFunctionCredentialPath
)

$hasFreshRegistration = @(
    $surfaceMatrix.powerShellLocalRegistration.success
    $surfaceMatrix.pythonLocalRegistration.success
    $surfaceMatrix.powerShellFunctionRegistration.success
    $surfaceMatrix.pythonFunctionRegistration.success
) -contains $true
$script:hasWaitedForPropagation = $false

function Wait-ForPostRegistrationPropagation {
    param(
        [Parameter(Mandatory)]
        [bool]$HasFreshRegistration,

        [Parameter(Mandatory)]
        [int]$DelaySeconds
    )

    if (-not $HasFreshRegistration -or $script:hasWaitedForPropagation -or $DelaySeconds -le 0) {
        return
    }

    # Newly registered passkeys can take a few seconds before Entra accepts them for login.
    # When this script performs login right after registration, wait briefly before the first attempt.
    Start-Sleep -Seconds $DelaySeconds
    $script:hasWaitedForPropagation = $true
}

$powerShellLoginResult = $null
if (-not $SkipPowerShellLogin) {
    if (-not $preferredCredentialPath) {
        throw 'No credential file was produced before PowerShell local login. Enable at least one registration path first.'
    }

    $surfaceMatrix.powerShellLocalLogin.attempted = $true
    $powerShellLoginScript = Join-Path $repoRoot 'powershell\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1'
    $loginParams = @{
        KeyFilePath       = $preferredCredentialPath
        KeyVaultTenantId  = $TenantId
        PassThru          = $true
    }
    if ($KeyVaultAccessToken) {
        $loginParams.KeyVaultAccessToken = $KeyVaultAccessToken
    }

    Wait-ForPostRegistrationPropagation -HasFreshRegistration $hasFreshRegistration -DelaySeconds $PostRegistrationLoginDelaySeconds

    $powerShellLoginResult = Invoke-WithRetry -Label 'PowerShell local login' -RetryCount $PostRegistrationLoginRetryCount -DelaySeconds $PostRegistrationLoginDelaySeconds -Action {
        & $powerShellLoginScript @loginParams
    }
    $surfaceMatrix.powerShellLocalLogin.success = [bool]$powerShellLoginResult.Success
    $surfaceMatrix.powerShellLocalLogin.detail = $powerShellLoginResult.CookieType
    if ($powerShellLoginResult.Success -and -not $EstsAuthCookie -and (Get-Variable -Name ESTSAUTH -Scope Global -ErrorAction SilentlyContinue)) {
        $EstsAuthCookie = [string](Get-Variable -Name ESTSAUTH -Scope Global).Value
    }
} else {
    $surfaceMatrix.powerShellLocalLogin.detail = 'Skipped by request.'
}

$pythonLoginResult = $null
if (-not $SkipPythonLogin) {
    if (-not $preferredCredentialPath) {
        throw 'No credential file was produced before Python local login. Enable at least one registration path first.'
    }

    $surfaceMatrix.pythonLocalLogin.attempted = $true
    Wait-ForPostRegistrationPropagation -HasFreshRegistration $hasFreshRegistration -DelaySeconds $PostRegistrationLoginDelaySeconds

    $pythonLoginResult = Invoke-WithRetry -Label 'Python local login' -RetryCount $PostRegistrationLoginRetryCount -DelaySeconds $PostRegistrationLoginDelaySeconds -Action {
        Invoke-PythonLogin -CredentialPath $preferredCredentialPath
    }
    $surfaceMatrix.pythonLocalLogin.success = [bool]$pythonLoginResult.success
    $surfaceMatrix.pythonLocalLogin.detail = $pythonLoginResult.cookieType
    if ($pythonLoginResult.success -and -not $EstsAuthCookie -and $pythonLoginResult.PSObject.Properties.Name -contains 'estsAuthCookie' -and $pythonLoginResult.estsAuthCookie) {
        $EstsAuthCookie = [string]$pythonLoginResult.estsAuthCookie
    }
} else {
    $surfaceMatrix.pythonLocalLogin.detail = 'Skipped by request.'
}

$powerShellFunctionLoginResult = $null
if ($PowerShellFunctionLoginUrl) {
    if (-not $preferredCredentialPath) {
        throw 'No credential file was produced before PowerShell Function login. Enable at least one registration path first.'
    }

    $surfaceMatrix.powerShellFunctionLogin.attempted = $true
    $credential = Get-Content -LiteralPath $preferredCredentialPath -Raw | ConvertFrom-Json
    Wait-ForPostRegistrationPropagation -HasFreshRegistration $hasFreshRegistration -DelaySeconds $PostRegistrationLoginDelaySeconds

    $powerShellFunctionLoginResult = Invoke-WithRetry -Label 'PowerShell Function login' -RetryCount $PostRegistrationLoginRetryCount -DelaySeconds $PostRegistrationLoginDelaySeconds -Action {
        Invoke-FunctionPasskeyLogin -Uri $PowerShellFunctionLoginUrl -Credential $credential
    }
    $surfaceMatrix.powerShellFunctionLogin.success = [bool]$powerShellFunctionLoginResult.success
    $surfaceMatrix.powerShellFunctionLogin.detail = $powerShellFunctionLoginResult.cookieType
    if ($powerShellFunctionLoginResult.success -and -not $EstsAuthCookie -and $powerShellFunctionLoginResult.estsAuthCookie) {
        $EstsAuthCookie = [string]$powerShellFunctionLoginResult.estsAuthCookie
    }
} else {
    $surfaceMatrix.powerShellFunctionLogin.detail = 'No PowerShell function login URL was supplied.'
}

$pythonFunctionLoginResult = $null
if ($PythonFunctionLoginUrl) {
    if (-not $preferredCredentialPath) {
        throw 'No credential file was produced before Python Function login. Enable at least one registration path first.'
    }

    $surfaceMatrix.pythonFunctionLogin.attempted = $true
    $credential = Get-Content -LiteralPath $preferredCredentialPath -Raw | ConvertFrom-Json
    Wait-ForPostRegistrationPropagation -HasFreshRegistration $hasFreshRegistration -DelaySeconds $PostRegistrationLoginDelaySeconds

    $pythonFunctionLoginResult = Invoke-WithRetry -Label 'Python Function login' -RetryCount $PostRegistrationLoginRetryCount -DelaySeconds $PostRegistrationLoginDelaySeconds -Action {
        Invoke-FunctionPasskeyLogin -Uri $PythonFunctionLoginUrl -Credential $credential
    }
    $surfaceMatrix.pythonFunctionLogin.success = [bool]$pythonFunctionLoginResult.success
    $surfaceMatrix.pythonFunctionLogin.detail = $pythonFunctionLoginResult.cookieType
    if ($pythonFunctionLoginResult.success -and -not $EstsAuthCookie -and $pythonFunctionLoginResult.estsAuthCookie) {
        $EstsAuthCookie = [string]$pythonFunctionLoginResult.estsAuthCookie
    }
} else {
    $surfaceMatrix.pythonFunctionLogin.detail = 'No Python function login URL was supplied.'
}

if ($PythonLocalRegistrationMode -eq 'estsauth') {
    $surfaceMatrix.pythonLocalRegistration.attempted = $true
    if (-not $EstsAuthCookie) {
        throw 'Python ESTSAUTH registration requires -EstsAuthCookie or a successful login surface that returns one.'
    }

    $pythonRegistration = Invoke-PythonLocalRegistration -Mode $PythonLocalRegistrationMode -OutputPath $pythonLocalCredentialPath -Cookie $EstsAuthCookie
    if (-not $pythonRegistration.success) {
        throw 'Python local registration reported failure.'
    }
    $registrationResults.pythonLocal = $pythonLocalCredentialPath
    $surfaceMatrix.pythonLocalRegistration.success = $true
    $surfaceMatrix.pythonLocalRegistration.detail = $pythonLocalCredentialPath
}

$preferredCredentialPath = Resolve-PreferredCredentialPath -Paths @(
    $directCredentialPath,
    $pythonLocalCredentialPath,
    $powerShellFunctionCredentialPath,
    $pythonFunctionCredentialPath
)

if (-not $preferredCredentialPath) {
    throw 'No credential file was produced. Provide at least one registration path to validate.'
}

$result = [PSCustomObject]@{
    outputDirectory          = $OutputDirectory
    preferredCredentialPath  = $preferredCredentialPath
    registrationResults      = [PSCustomObject]$registrationResults
    surfaceMatrix            = [PSCustomObject]$surfaceMatrix
    powerShellLoginResult    = $powerShellLoginResult
    pythonLoginResult        = $pythonLoginResult
    powerShellFunctionLoginResult = $powerShellFunctionLoginResult
    pythonFunctionLoginResult = $pythonFunctionLoginResult
    estsAuthCookie           = $EstsAuthCookie
}

if ($PassThru) {
    Write-Output $result
} else {
    $result | ConvertTo-Json -Depth 10
}
