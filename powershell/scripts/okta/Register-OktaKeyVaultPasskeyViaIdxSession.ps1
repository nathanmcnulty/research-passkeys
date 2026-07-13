#Requires -Version 7.0

<#
.SYNOPSIS
    POC: enrolls an Okta WebAuthn credential whose private key is in Azure Key Vault.

.DESCRIPTION
    This script is a short-lived browser-to-script handoff for testing against an Okta
    Identity Engine tenant. It does not authenticate to Okta. Instead, the user completes
    the normal password/MFA step-up in the Okta browser UI, then supplies the current IDX
    stateHandle, the browser Cookie request header, and the WebAuthn authenticator ID.

    The script uses the dynamic remediation links returned by IDX to request registration
    options, creates an EC P-256 key in Azure Key Vault, builds a packed WebAuthn
    attestation, and submits it to Okta. The Key Vault private key is never exported.

    IDX endpoints and browser session artifacts are internal implementation details. This
    is a development POC only; a browser extension should use the normal WebAuthn ceremony
    rather than collecting browser cookies. Treat CookieHeader and StateHandle as secrets.

.PARAMETER OktaDomain
    Okta org host name, for example contoso.okta.com. Do not include a path.

.PARAMETER CookieHeader
    The complete Cookie request-header value copied from an authenticated IDX request in
    the browser. Do not save it in a script, history, or source control.

.PARAMETER StateHandle
    Current stateHandle copied after the browser has completed any required step-up and
    is offering the WebAuthn authenticator enrollment remediation.

.PARAMETER AuthenticatorId
    The WebAuthn authenticator ID (for example auts...). It is the id used by the browser's
    POST /idp/idx/credential/enroll request.

.PARAMETER KeyVaultName
    Azure Key Vault that will hold the new P-256 credential private key.

.PARAMETER KeyVaultAccessToken
    Optional Key Vault access token. If omitted, Az.Accounts and Azure CLI are tried.

.NOTES
    The flow has been derived from an Okta browser HAR. It intentionally emulates a
    cross-platform authenticator (transport usb) and reports any direct-attestation policy
    rejection from the tenant.
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
    [string]$AuthenticatorId,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('usb', 'internal')]
    [string]$Transport = 'usb',

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

$moduleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\modules'
Import-Module (Join-Path -Path $moduleRoot -ChildPath 'Passkey.Common\Passkey.Common.psm1') -Force

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

function Get-HeaderValue {
    param([hashtable]$Headers, [string]$Name)

    foreach ($key in $Headers.Keys) {
        if ($key -ieq $Name) { return $Headers[$key] }
    }
    return $null
}

function Invoke-OktaIdxJson {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)]$Body,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )

    try {
        return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -WebSession $WebSession `
            -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 10 -Compress)
    } catch {
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Okta IDX request failed for $Uri`: $detail"
    }
}

function Get-RemediationHref {
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$OktaHost
    )

    $remediation = @($Response.remediation.value | Where-Object { $_.name -eq $Name }) | Select-Object -First 1
    if (-not $remediation -or -not $remediation.href) {
        throw "IDX response did not offer the '$Name' remediation. Complete the required browser step-up again and copy a fresh stateHandle."
    }
    $uri = [Uri]$remediation.href
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne $OktaHost) {
        throw "Refusing remediation URL outside the specified Okta domain: $($remediation.href)"
    }
    return $uri.AbsoluteUri
}

$CookieHeader = ConvertFrom-SensitiveInput $CookieHeader
$StateHandle = ConvertFrom-SensitiveInput $StateHandle
$inputUri = if ($OktaDomain -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { [Uri]$OktaDomain } else { [Uri]("https://$OktaDomain") }
if (-not $inputUri.Host -or $inputUri.AbsolutePath -ne '/' -or $inputUri.Query -or $inputUri.Fragment -or $inputUri.UserInfo) {
    throw 'OktaDomain must be a host name only, such as contoso.okta.com.'
}
$oktaHost = $inputUri.Host
$origin = "https://$oktaHost"

if ([string]::IsNullOrWhiteSpace($CookieHeader) -or [string]::IsNullOrWhiteSpace($StateHandle)) {
    throw 'CookieHeader and StateHandle cannot be empty.'
}
if ([string]::IsNullOrWhiteSpace($AuthenticatorId)) {
    throw 'AuthenticatorId cannot be empty.'
}

$idxHeaders = @{
    Accept       = 'application/json'
    Origin       = $origin
    Referer      = "$origin/"
    'User-Agent' = $UserAgent
}
foreach ($key in $AdditionalHeaders.Keys) {
    if ($key -in @('Authorization', 'Cookie', 'Host', 'Content-Length')) {
        throw "AdditionalHeaders may not override '$key'."
    }
    $idxHeaders[$key] = $AdditionalHeaders[$key]
}
$webSession = New-OktaWebSession -CookieHeader $CookieHeader -Origin $origin -UserAgent $UserAgent

Write-Host '=== Okta IDX WebAuthn registration POC ===' -ForegroundColor Cyan
Write-Host 'Requesting registration options from the active browser transaction...' -ForegroundColor Yellow
$selectionResponse = Invoke-OktaIdxJson -Uri "$origin/idp/idx/credential/enroll" -Headers $idxHeaders -WebSession $webSession -Body @{
    authenticator = @{ id = $AuthenticatorId }
    stateHandle   = $StateHandle
}

$activation = $selectionResponse.currentAuthenticator.value.contextualData.activationData
if (-not $activation -or -not $activation.challenge -or -not $activation.user -or -not $activation.pubKeyCredParams) {
    throw 'Okta did not return WebAuthn activation data. The browser state is expired or is not in the enrollment step.'
}
$finishUri = Get-RemediationHref -Response $selectionResponse -Name 'enroll-authenticator' -OktaHost $oktaHost

$supportedAlgorithms = @($activation.pubKeyCredParams | ForEach-Object { $_.alg })
if (-7 -notin $supportedAlgorithms) {
    throw "Okta did not offer ES256 (-7). This POC currently requires ES256; offered algorithms: $($supportedAlgorithms -join ', ')."
}
if ($activation.authenticatorSelection.userVerification -and $activation.authenticatorSelection.userVerification -ne 'required') {
    Write-Warning "Okta returned userVerification='$($activation.authenticatorSelection.userVerification)'; the POC will still report UV in authenticator data."
}

$rpId = if ($activation.rp.id) { [string]$activation.rp.id } else { $oktaHost }
$kvToken = Get-KeyVaultToken -AccessToken $KeyVaultAccessToken
if (-not $KeyVaultKeyName) {
    $safeUser = ([string]$activation.user.name -replace '[^A-Za-z0-9-]', '').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($safeUser)) { $safeUser = 'oktauser' }
    if ($safeUser.Length -gt 12) { $safeUser = $safeUser.Substring(0, 12) }
    $KeyVaultKeyName = "okta-pk-$safeUser-$(Get-Random -Minimum 100000 -Maximum 1000000)"
}

Write-Host "Creating Key Vault key '$KeyVaultKeyName'..." -ForegroundColor Yellow
$kvHeaders = @{ Authorization = "Bearer $kvToken"; 'Content-Type' = 'application/json' }
$keyCreate = Invoke-RestMethod -Method Post -Uri "https://$KeyVaultName.vault.azure.net/keys/$KeyVaultKeyName/create?api-version=7.4" `
    -Headers $kvHeaders -Body (@{ kty = 'EC'; crv = 'P-256'; key_ops = @('sign', 'verify') } | ConvertTo-Json)
$publicKeyX = [byte[]](ConvertFrom-Base64Url $keyCreate.key.x)
$publicKeyY = [byte[]](ConvertFrom-Base64Url $keyCreate.key.y)

# Credential key material is in Key Vault. The short-lived batch key below exists only to
# create a packed attestation statement; it is disposed immediately after registration.
$credentialIdBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($credentialIdBytes)
$credentialId = ConvertTo-Base64Url $credentialIdBytes
$coseKey = [ordered]@{ 1 = 2; 3 = -7; -1 = 1; -2 = $publicKeyX; -3 = $publicKeyY }
$coseKeyBytes = [byte[]](New-CBOREncoded $coseKey)
$rpHash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($rpId))
$flags = [byte[]]@(0x45) # user present, user verified, attested credential data
$counter = [byte[]]@(0, 0, 0, 0)
$aaguid = [byte[]]::new(16)
$credentialLength = [BitConverter]::GetBytes([uint16]$credentialIdBytes.Length)
[Array]::Reverse($credentialLength)
[byte[]]$authenticatorData = $rpHash + $flags + $counter + $aaguid + $credentialLength + $credentialIdBytes + $coseKeyBytes

# Okta returns a base64url challenge. Unlike the Entra flow, WebAuthn clientData preserves
# this value as-is rather than base64url-encoding its UTF-8 representation a second time.
$clientDataJson = [ordered]@{
    type        = 'webauthn.create'
    challenge   = [string]$activation.challenge
    origin      = $origin
    crossOrigin = $false
} | ConvertTo-Json -Compress
$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientDataJson)
$signatureBase = $authenticatorData + [System.Security.Cryptography.SHA256]::HashData($clientDataBytes)

$batchKey = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
$certificate = $null
try {
    $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Key Vault Passkey POC, OU=WebAuthn Attestation, O=Research Passkeys, C=US',
        $batchKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $certificate = $certificateRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
    $attestationSignature = $batchKey.SignData($signatureBase, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    $attestation = [ordered]@{
        fmt      = 'packed'
        attStmt  = [ordered]@{ alg = -7; sig = [byte[]]$attestationSignature; x5c = @(, [byte[]]$certificate.RawData) }
        authData = [byte[]]$authenticatorData
    }
    $attestationBytes = [byte[]](New-CBOREncoded $attestation)
} finally {
    if ($certificate) { $certificate.Dispose() }
    $batchKey.Dispose()
}

Write-Host 'Submitting Key Vault-backed WebAuthn attestation to Okta...' -ForegroundColor Yellow
$completion = Invoke-OktaIdxJson -Uri $finishUri -Headers $idxHeaders -WebSession $webSession -Body @{
    credentials = @{
        clientData       = [Convert]::ToBase64String($clientDataBytes)
        attestation      = [Convert]::ToBase64String($attestationBytes)
        transports       = (@($Transport) | ConvertTo-Json -Compress)
        clientExtensions = (@{ credProps = @{ rk = $false } } | ConvertTo-Json -Compress)
    }
    stateHandle = $selectionResponse.stateHandle
}

if (-not $completion.success) {
    throw 'Okta did not return a success remediation. The Key Vault key remains available for inspection, but no credential record was written.'
}

$record = [ordered]@{
    credentialId = $credentialId
    relyingParty = $rpId
    url          = $origin
    userName     = [string]$activation.user.name
    keyVault     = [ordered]@{
        vaultName = $KeyVaultName
        keyName   = $KeyVaultKeyName
        keyId     = $keyCreate.key.kid
    }
    okta = [ordered]@{
        userId    = [string]$activation.user.id
        transport = $Transport
    }
}
if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) ("okta-passkey-$($KeyVaultKeyName).json")
}
$record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM

Write-Host '✓ Okta accepted the registration.' -ForegroundColor Green
Write-Host "  Credential record: $OutputPath" -ForegroundColor Green
Write-Host "  Key Vault key: $($keyCreate.key.kid)" -ForegroundColor Gray
Write-Warning 'Delete the browser session artifacts you copied. The resulting credential is a POC and must be tested with an explicit Okta assertion flow.'

[pscustomobject]$record
