[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionBaseUrl,

    [Parameter(Mandatory)]
    [object]$FunctionKey,

    [Parameter()]
    [string]$CredentialJson,

    [Parameter()]
    [string]$CredentialPath,

    [Parameter()]
    [string]$AuthUrl,

    [Parameter()]
    [string]$KeyVaultName,

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

if (-not $CredentialJson -and -not $CredentialPath) {
    throw 'Provide either -CredentialJson or -CredentialPath.'
}

if ($CredentialJson) {
    $credential = $CredentialJson | ConvertFrom-Json -AsHashtable
} else {
    $credential = Get-Content -LiteralPath $CredentialPath -Raw | ConvertFrom-Json -AsHashtable
}

$body = @{
    credential = $credential
}
if ($AuthUrl) {
    $body.authUrl = $AuthUrl
}
if ($KeyVaultName) {
    $body.keyVaultName = $KeyVaultName
}
if ($KeyVaultKeyName) {
    $body.keyVaultKeyName = $KeyVaultKeyName
}

$response = Invoke-RestMethod `
    -Method POST `
    -Uri "$($FunctionBaseUrl.TrimEnd('/'))/api/passkeys/login" `
    -Headers @{ 'x-functions-key' = (ConvertTo-PlainText -Value $FunctionKey) } `
    -ContentType 'application/json' `
    -Body ($body | ConvertTo-Json -Depth 20)

if ($PassThru) {
    Write-Output $response
} else {
    $response | ConvertTo-Json -Depth 20
}
