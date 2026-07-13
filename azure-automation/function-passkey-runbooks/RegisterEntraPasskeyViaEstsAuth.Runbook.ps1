[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionBaseUrl,

    [Parameter(Mandatory)]
    [object]$FunctionKey,

    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [object]$EstsAuthCookie,

    [Parameter()]
    [string]$DisplayName = 'Automation Runbook Passkey',

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function ConvertTo-PlainText {
    param([Parameter(Mandatory)] [object]$Value)

    if ($Value -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $Value).Password
    }

    return [string]$Value
}

$body = @{
    userPrincipalName = $UserPrincipalName
    estsAuth          = ConvertTo-PlainText -Value $EstsAuthCookie
    displayName       = $DisplayName
}
if ($KeyVaultKeyName) {
    $body.keyVaultKeyName = $KeyVaultKeyName
}

$response = Invoke-RestMethod `
    -Method POST `
    -Uri "$($FunctionBaseUrl.TrimEnd('/'))/api/entra/passkeys/register/estsauth" `
    -Headers @{ 'x-functions-key' = (ConvertTo-PlainText -Value $FunctionKey) } `
    -ContentType 'application/json' `
    -Body ($body | ConvertTo-Json -Depth 10)

if ($PassThru) {
    Write-Output $response
} else {
    $response | ConvertTo-Json -Depth 20
}
