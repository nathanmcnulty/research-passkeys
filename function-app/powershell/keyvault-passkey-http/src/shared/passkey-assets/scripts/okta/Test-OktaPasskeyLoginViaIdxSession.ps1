#Requires -Version 7.0

<#
.SYNOPSIS
    POC: tests an Okta passkey assertion signed by a key held in Azure Key Vault.

.DESCRIPTION
    This is the login counterpart to Register-OktaKeyVaultPasskeyViaIdxSession.ps1.
    Start an Okta sign-in in a browser, select the WebAuthn authenticator, and pause the
    browser before it submits /idp/idx/challenge/answer. Copy the current stateHandle,
    challenge, and Cookie header into this script. It creates authenticator data and a
    WebAuthn clientDataJSON value, signs the assertion input through Key Vault, and sends
    the resulting assertion to Okta's active IDX transaction.

    The script deliberately stops after Okta accepts the assertion. It does not attempt
    to exchange an authorization code or persist browser session material. IDX and copied
    cookies are internal development artifacts; this is not the production extension API.

.PARAMETER OktaDomain
    Okta org host name, for example contoso.okta.com.

.PARAMETER CookieHeader
    Complete Cookie request-header value from the active browser IDX request.

.PARAMETER StateHandle
    Current stateHandle from the WebAuthn challenge response/request.

.PARAMETER Challenge
    Base64url challenge from contextualData.challenge. Preserve it exactly; do not decode
    and encode it again.

.PARAMETER CredentialId
    Base64url credential ID from the registration record.

.PARAMETER KeyVaultName
    Key Vault containing the credential private key.

.PARAMETER KeyVaultKeyName
    Key name containing the credential private key.

.PARAMETER KeyVaultKeyId
    Optional versioned Key Vault key ID from the registration record. Use it when the
    key name has been rotated after the passkey was enrolled.

.PARAMETER CredentialFilePath
    Optional registration-record JSON path. Values from the file fill CredentialId,
    KeyVaultName, KeyVaultKeyName, and relyingParty when those parameters are omitted.

.PARAMETER KeyVaultAccessToken
    Optional Key Vault access token. If omitted, Az.Accounts and Azure CLI are tried.

.PARAMETER SignCount
    Four-byte authenticator signature counter. The registration POC starts at zero.
    Persist and increment this value for a production authenticator implementation.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OktaDomain,

    [Parameter(Mandatory)]
    [object]$CookieHeader,

    [Parameter(Mandatory)]
    [object]$StateHandle,

    [Parameter(Mandatory)]
    [string]$Challenge,

    [Parameter()]
    [string]$CredentialId,

    [Parameter()]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$KeyVaultKeyId,

    [Parameter()]
    [string]$CredentialFilePath,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [ValidateRange(0, [uint32]::MaxValue)]
    [uint32]$SignCount = 0,

    [Parameter()]
    [string]$Origin,

    [Parameter()]
    [hashtable]$AdditionalHeaders = @{},

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-SensitiveInput {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $Value).Password
    }
    return [string]$Value
}

function New-OktaWebSession {
    param(
        [Parameter(Mandatory)][string]$CookieHeader,
        [Parameter(Mandatory)][string]$Origin,
        [Parameter(Mandatory)][string]$UserAgent
    )

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = $UserAgent
    $cookieCount = 0
    foreach ($part in ($CookieHeader -split ';\s*')) {
        $separator = $part.IndexOf('=')
        if ($separator -le 0) { continue }
        $name = $part.Substring(0, $separator).Trim()
        $value = $part.Substring($separator + 1).Trim()
        if (-not $name) { continue }
        try {
            $cookie = [System.Net.Cookie]::new($name, $value, '/', ([Uri]$Origin).Host)
            $session.Cookies.Add([Uri]($Origin + '/'), $cookie)
            $cookieCount++
        } catch {
            throw "Could not import browser cookie '$name': $($_.Exception.Message)"
        }
    }
    if ($cookieCount -eq 0) { throw 'CookieHeader did not contain any importable cookies.' }
    Write-Verbose "Imported $cookieCount browser cookies into a PowerShell WebRequestSession."
    return $session
}

function Get-KeyVaultToken {
    param([string]$AccessToken)

    if ($AccessToken) { return $AccessToken }
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $token = Get-AzAccessToken -ResourceUrl 'https://vault.azure.net' -ErrorAction Stop
            if ($token.Token -is [securestring]) {
                return [System.Net.NetworkCredential]::new('', $token.Token).Password
            }
            return $token.Token
        } catch {
            Write-Verbose "Az.Accounts Key Vault token acquisition failed: $($_.Exception.Message)"
        }
    }
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $result = az account get-access-token --resource https://vault.azure.net --output json 2>$null
        if ($LASTEXITCODE -eq 0) { return ($result | ConvertFrom-Json).accessToken }
    }
    throw 'Could not get a Key Vault token. Use Connect-AzAccount, az login, or -KeyVaultAccessToken.'
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory)][string]$Value)

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    $base64 += '=' * ((4 - ($base64.Length % 4)) % 4)
    [Convert]::FromBase64String($base64)
}

function ConvertFrom-IeeeToDer {
    param([Parameter(Mandatory)][byte[]]$IeeeSignature)

    if ($IeeeSignature.Length -ne 64) {
        throw "Key Vault returned an unexpected ES256 signature length: $($IeeeSignature.Length) bytes."
    }
    $r = [byte[]]$IeeeSignature[0..31]
    $s = [byte[]]$IeeeSignature[32..63]
    while ($r.Length -gt 1 -and $r[0] -eq 0) { $r = [byte[]]$r[1..($r.Length - 1)] }
    while ($s.Length -gt 1 -and $s[0] -eq 0) { $s = [byte[]]$s[1..($s.Length - 1)] }
    if ($r[0] -ge 0x80) { $r = [byte[]](@(0) + $r) }
    if ($s[0] -ge 0x80) { $s = [byte[]](@(0) + $s) }
    [byte[]](@(0x30, ($r.Length + $s.Length + 4), 0x02, $r.Length) + $r + @(0x02, $s.Length) + $s)
}

function Invoke-OktaAssertion {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)]$Body,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )

    try {
        return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -WebSession $WebSession -ContentType 'application/json' `
            -Body ($Body | ConvertTo-Json -Depth 10 -Compress)
    } catch {
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Okta assertion request failed: $detail"
    }
}

if ($CredentialFilePath) {
    if (-not (Test-Path -LiteralPath $CredentialFilePath -PathType Leaf)) {
        throw "Credential file not found: $CredentialFilePath"
    }
    $record = Get-Content -LiteralPath $CredentialFilePath -Raw | ConvertFrom-Json
    if (-not $CredentialId) { $CredentialId = [string]$record.credentialId }
    if (-not $KeyVaultName) { $KeyVaultName = [string]$record.keyVault.vaultName }
    if (-not $KeyVaultKeyName) { $KeyVaultKeyName = [string]$record.keyVault.keyName }
    if (-not $KeyVaultKeyId) { $KeyVaultKeyId = [string]$record.keyVault.keyId }
    if (-not $Origin -and $record.url) { $Origin = [string]$record.url }
}

$CookieHeader = ConvertFrom-SensitiveInput $CookieHeader
$StateHandle = ConvertFrom-SensitiveInput $StateHandle
if ([string]::IsNullOrWhiteSpace($CredentialId)) { throw 'CredentialId or CredentialFilePath is required.' }
if ([string]::IsNullOrWhiteSpace($KeyVaultName) -or [string]::IsNullOrWhiteSpace($KeyVaultKeyName)) {
    throw 'KeyVaultName and KeyVaultKeyName or CredentialFilePath are required.'
}

$domainUri = if ($OktaDomain -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { [Uri]$OktaDomain } else { [Uri]("https://$OktaDomain") }
if (-not $domainUri.Host -or $domainUri.AbsolutePath -ne '/' -or $domainUri.Query -or $domainUri.Fragment -or $domainUri.UserInfo) {
    throw 'OktaDomain must be a host name only, such as contoso.okta.com.'
}
$oktaHost = $domainUri.Host
if (-not $Origin) { $Origin = "https://$oktaHost" }
$originUri = [Uri]$Origin
if ($originUri.Scheme -ne 'https' -or $originUri.Host -ne $oktaHost -or $originUri.AbsolutePath -ne '/') {
    throw 'Origin must be the HTTPS origin of OktaDomain.'
}

if ($Challenge -notmatch '^[A-Za-z0-9_-]+$') {
    throw 'Challenge must be Okta''s base64url challenge string, copied without modification.'
}

$headers = @{
    Accept       = 'application/json'
    Origin       = $Origin
    Referer      = "$Origin/"
    'User-Agent' = $UserAgent
}
foreach ($key in $AdditionalHeaders.Keys) {
    if ($key -in @('Authorization', 'Cookie', 'Host', 'Content-Length')) {
        throw "AdditionalHeaders may not override '$key'."
    }
    $headers[$key] = $AdditionalHeaders[$key]
}
$webSession = New-OktaWebSession -CookieHeader $CookieHeader -Origin $Origin -UserAgent $UserAgent

$rpHash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($oktaHost))
$counterBytes = [BitConverter]::GetBytes([uint32]$SignCount)
[Array]::Reverse($counterBytes)
[byte[]]$authenticatorData = $rpHash + [byte[]]@(0x05) + [byte[]]$counterBytes

$clientDataJson = [ordered]@{
    type        = 'webauthn.get'
    challenge   = $Challenge
    origin      = $Origin
    crossOrigin = $false
} | ConvertTo-Json -Compress
$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientDataJson)
$clientDataHash = [System.Security.Cryptography.SHA256]::HashData($clientDataBytes)
$signedData = [byte[]]($authenticatorData + $clientDataHash)
$signedHash = [System.Security.Cryptography.SHA256]::HashData($signedData)

$kvToken = Get-KeyVaultToken -AccessToken $KeyVaultAccessToken
$signUri = if ($KeyVaultKeyId) {
    $keyIdUri = [Uri]$KeyVaultKeyId
    if ($keyIdUri.Scheme -ne 'https' -or $keyIdUri.Host -ne "$KeyVaultName.vault.azure.net" -or $keyIdUri.AbsolutePath -notmatch '^/keys/[^/]+/[^/]+$') {
        throw 'KeyVaultKeyId must be a versioned HTTPS Key Vault key ID in the selected vault.'
    }
    "$($KeyVaultKeyId.TrimEnd('/'))/sign?api-version=7.4"
} else {
    "https://$KeyVaultName.vault.azure.net/keys/$KeyVaultKeyName/sign?api-version=7.4"
}
$signBody = @{ alg = 'ES256'; value = (ConvertTo-Base64Url $signedHash) } | ConvertTo-Json
$kvHeaders = @{ Authorization = "Bearer $kvToken"; 'Content-Type' = 'application/json' }
Write-Host 'Signing the Okta assertion with Azure Key Vault...' -ForegroundColor Cyan
$signResponse = Invoke-RestMethod -Method Post -Uri $signUri -Headers $kvHeaders -Body $signBody
if (-not $signResponse.value) { throw 'Key Vault returned an empty signature.' }
$derSignature = ConvertFrom-IeeeToDer (ConvertFrom-Base64Url $signResponse.value)

$assertionBody = @{
    credentials = @{
        clientData       = [Convert]::ToBase64String($clientDataBytes)
        authenticatorData = [Convert]::ToBase64String($authenticatorData)
        signatureData    = [Convert]::ToBase64String($derSignature)
    }
    stateHandle = $StateHandle
}

Write-Host 'Submitting the Key Vault-backed assertion to Okta...' -ForegroundColor Yellow
$response = Invoke-OktaAssertion -Uri "$Origin/idp/idx/challenge/answer" -Headers $headers -WebSession $webSession -Body $assertionBody
if (-not $response.success) {
    $message = @($response.messages.value.message) -join '; '
    if (-not $message) { $message = 'Okta returned no success remediation.' }
    throw "Okta rejected the passkey assertion: $message"
}

Write-Host '✓ Okta accepted the Key Vault-backed passkey assertion.' -ForegroundColor Green
Write-Host "  Success remediation: $($response.success.name)" -ForegroundColor Gray
Write-Host "  Credential ID: $CredentialId" -ForegroundColor Gray
Write-Host '  The browser/session redirect step was intentionally left to the caller.' -ForegroundColor Gray

[pscustomobject]@{
    Success      = $true
    CredentialId = $CredentialId
    UserName     = if ($record) { [string]$record.userName } else { $null }
    SuccessStep  = [string]$response.success.name
}
