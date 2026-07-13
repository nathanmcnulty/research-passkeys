#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end Okta IDX login test using a Key Vault-backed passkey.

.DESCRIPTION
    Starts an Okta authorization transaction in a fresh PowerShell WebRequestSession,
    extracts the IDX state token from the login page, submits the supplied username,
    selects the enrolled WebAuthn authenticator, signs the challenge with the credential
    key in Azure Key Vault, and submits the assertion to Okta.

    Some Okta policies require the password before allowing a passkey. Supply -Password
    as a SecureString when required; if omitted, the script attempts passkey selection
    directly. The script reports whether Okta accepted the assertion and the resulting
    success redirect status. It does not print access tokens or authorization codes.

    The default client and callback are the built-in account-settings client observed in
    the developer-tenant HAR. Override -ClientId and -RedirectUri for another Okta org or
    another existing OIDC client. This is a development test harness for IDX, not a
    supported production integration API.

.PARAMETER OktaDomain
    Okta org host name, for example your-tenant.okta.com.

.PARAMETER UserName
    Okta username to submit to the IDX identify remediation.

.PARAMETER CredentialFilePath
    Optional registration-record JSON produced by Register-OktaKeyVaultPasskeyViaIdxSession.ps1.

.PARAMETER CredentialId
    Base64url credential ID. Required when CredentialFilePath is not supplied.

.PARAMETER KeyVaultName
    Key Vault name. Required when CredentialFilePath is not supplied.

.PARAMETER KeyVaultKeyName
    Key Vault key name. Required when CredentialFilePath is not supplied.

.PARAMETER KeyVaultKeyId
    Optional versioned Key Vault key ID. Supplying the ID from the registration record
    prevents a later key rotation from breaking validation against Okta's stored public key.

.PARAMETER RelyingParty
    WebAuthn RP ID. Defaults to the record value or the Okta host.

.PARAMETER KeyVaultAccessToken
    Optional access token for https://vault.azure.net. Otherwise Az.Accounts or Azure CLI
    is used.

.PARAMETER Password
    Optional user password. Use Read-Host -AsSecureString. Required when the org policy
    requires password before WebAuthn.

.PARAMETER ClientId
    Existing OIDC client ID used to start the authorization transaction.

.PARAMETER RedirectUri
    Callback registered for ClientId. Defaults to the account-settings callback observed
    in the developer tenant.

.PARAMETER SignCount
    Authenticator signature counter to place in the assertion. Use a monotonically
    increasing value for repeated tests; the default is 1 for a newly registered key.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OktaDomain,

    [Parameter(Mandatory)]
    [string]$UserName,

    [Parameter()]
    [string]$CredentialFilePath,

    [Parameter()]
    [string]$CredentialId,

    [Parameter()]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$KeyVaultKeyId,

    [Parameter()]
    [string]$RelyingParty,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [securestring]$Password,

    [Parameter()]
    [string]$ClientId = 'okta.b8003760-1ca5-51b8-9404-85bb7ef9bc8c',

    [Parameter()]
    [string]$RedirectUri,

    [Parameter()]
    [ValidateRange(1, [uint32]::MaxValue)]
    [uint32]$SignCount = 1,

    [Parameter()]
    [hashtable]$AdditionalHeaders = @{},

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'
)

$ErrorActionPreference = 'Stop'

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

function ConvertFrom-SecureInput {
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [securestring]) { return [System.Net.NetworkCredential]::new('', $Value).Password }
    return [string]$Value
}

function Get-KeyVaultToken {
    param([string]$AccessToken)
    if ($AccessToken) { return $AccessToken }
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $result = Get-AzAccessToken -ResourceUrl 'https://vault.azure.net' -ErrorAction Stop
            if ($result.Token -is [securestring]) { return [System.Net.NetworkCredential]::new('', $result.Token).Password }
            return $result.Token
        } catch { Write-Verbose "Az.Accounts token acquisition failed: $($_.Exception.Message)" }
    }
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $result = az account get-access-token --resource https://vault.azure.net --output json 2>$null
        if ($LASTEXITCODE -eq 0) { return ($result | ConvertFrom-Json).accessToken }
    }
    throw 'Could not get a Key Vault token. Use Connect-AzAccount, az login, or -KeyVaultAccessToken.'
}

function ConvertFrom-IeeeToDer {
    param([Parameter(Mandatory)][byte[]]$IeeeSignature)
    if ($IeeeSignature.Length -ne 64) { throw "Expected a 64-byte ES256 Key Vault signature; got $($IeeeSignature.Length)." }
    $r = [byte[]]$IeeeSignature[0..31]
    $s = [byte[]]$IeeeSignature[32..63]
    while ($r.Length -gt 1 -and $r[0] -eq 0) { $r = [byte[]]$r[1..($r.Length - 1)] }
    while ($s.Length -gt 1 -and $s[0] -eq 0) { $s = [byte[]]$s[1..($s.Length - 1)] }
    if ($r[0] -ge 0x80) { $r = [byte[]](@(0) + $r) }
    if ($s[0] -ge 0x80) { $s = [byte[]](@(0) + $s) }
    [byte[]](@(0x30, ($r.Length + $s.Length + 4), 0x02, $r.Length) + $r + @(0x02, $s.Length) + $s)
}

function Get-Remediation {
    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)][string]$Name)
    @($Response.remediation.value | Where-Object { $_.name -eq $Name }) | Select-Object -First 1
}

function Get-SameOrgUri {
    param([Parameter(Mandatory)][string]$Href, [Parameter(Mandatory)][string]$Origin)
    $uri = [Uri]$Href
    $base = [Uri]$Origin
    if ($uri.Host -ne $base.Host -or $uri.Scheme -ne 'https') { throw "Refusing cross-origin Okta remediation URL: $Href" }
    $uri
}

function Invoke-IdxJson {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory)]$Body,
        [Parameter(Mandatory)][hashtable]$Headers
    )
    try {
        Invoke-RestMethod -Method Post -Uri $Uri -WebSession $Session -Headers $Headers `
            -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 12 -Compress)
    } catch {
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "IDX request failed for $Uri`: $detail"
    }
}

function Invoke-OktaRedirectFirstHop {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    # The success URL intentionally returns a redirect to the registered callback.
    # Use HttpClientHandler so that callback redirects are never followed implicitly.
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $true
    $handler.CookieContainer = $Session.Cookies
    $client = [System.Net.Http.HttpClient]::new($handler)
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, [Uri]$Uri)
    foreach ($key in $Headers.Keys) {
        if ($key -notin @('Host', 'Content-Length')) {
            [void]$request.Headers.TryAddWithoutValidation($key, [string]$Headers[$key])
        }
    }
    $response = $null
    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Location   = [string]$response.Headers.Location
        }
    } finally {
        if ($response) { $response.Dispose() }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

$record = $null
if ($CredentialFilePath) {
    if (-not (Test-Path -LiteralPath $CredentialFilePath -PathType Leaf)) { throw "Credential file not found: $CredentialFilePath" }
    $record = Get-Content -LiteralPath $CredentialFilePath -Raw | ConvertFrom-Json
    if (-not $CredentialId) { $CredentialId = [string]$record.credentialId }
    if (-not $KeyVaultName) { $KeyVaultName = [string]$record.keyVault.vaultName }
    if (-not $KeyVaultKeyName) { $KeyVaultKeyName = [string]$record.keyVault.keyName }
    if (-not $KeyVaultKeyId) { $KeyVaultKeyId = [string]$record.keyVault.keyId }
    if (-not $RelyingParty) { $RelyingParty = [string]$record.relyingParty }
}
if (-not $CredentialId -or -not $KeyVaultName -or -not $KeyVaultKeyName) {
    throw 'Provide CredentialId, KeyVaultName, and KeyVaultKeyName, or use CredentialFilePath.'
}

$domainUri = if ($OktaDomain -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { [Uri]$OktaDomain } else { [Uri]("https://$OktaDomain") }
if (-not $domainUri.Host -or $domainUri.AbsolutePath -ne '/' -or $domainUri.Query -or $domainUri.Fragment -or $domainUri.UserInfo) { throw 'OktaDomain must be a host name only.' }
$oktaHost = $domainUri.Host
$origin = "https://$oktaHost"
if (-not $RedirectUri) { $RedirectUri = "$origin/account-settings/callback" }
$redirect = [Uri]$RedirectUri
if ($redirect.Scheme -ne 'https' -or $redirect.Host -ne $oktaHost) { throw 'RedirectUri must use the Okta HTTPS origin.' }

$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$session.UserAgent = $UserAgent
$headers = @{
    Accept       = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    Origin       = $origin
    Referer      = "$origin/"
    'User-Agent' = $UserAgent
}
foreach ($key in $AdditionalHeaders.Keys) { $headers[$key] = $AdditionalHeaders[$key] }

# Start the same OIDC transaction used by the Okta end-user experience. This client is
# already present in the developer tenant; it is not a new customer app registration.
$pkceBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($pkceBytes)
$codeVerifier = ConvertTo-Base64Url $pkceBytes
$codeChallenge = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($codeVerifier)))
$stateBytes = [byte[]]::new(24)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
$oauthState = ConvertTo-Base64Url $stateBytes
$nonceBytes = [byte[]]::new(24)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
$nonce = ConvertTo-Base64Url $nonceBytes
$scope = 'openid profile email online_access okta.internal.enduser.read okta.myAccount.read okta.myAccount.manage okta.myAccount.profile.read okta.myAccount.profile.manage okta.enduser.dashboard.read okta.enduser.dashboard.manage'
$query = [System.Web.HttpUtility]::ParseQueryString([string]::Empty)
$query['client_id'] = $ClientId
$query['redirect_uri'] = $RedirectUri
$query['response_type'] = 'code'
$query['response_mode'] = 'query'
$query['scope'] = $scope
$query['state'] = $oauthState
$query['nonce'] = $nonce
$query['code_challenge'] = $codeChallenge
$query['code_challenge_method'] = 'S256'
# NameValueCollection's implicit PowerShell string conversion emits only its keys;
# use ToString() explicitly so every OAuth parameter is sent (matching the browser HAR).
$authorizeUri = "$origin/oauth2/v1/authorize?$($query.ToString())"

Write-Host 'Starting Okta login transaction...' -ForegroundColor Cyan
$loginPage = Invoke-WebRequest -Method Get -Uri $authorizeUri -WebSession $session -Headers $headers -MaximumRedirection 10
$stateMatch = [regex]::Match($loginPage.Content, "var\s+stateToken\s*=\s*'([^']+)'")
if (-not $stateMatch.Success) { throw 'Could not extract Okta stateToken from the authorization page.' }
$stateToken = [regex]::Replace($stateMatch.Groups[1].Value, '\\x([0-9a-fA-F]{2})', { param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16) })

$idxHeaders = @{
    Accept       = 'application/ion+json; okta-version=1.0.0'
    Origin       = $origin
    Referer      = $authorizeUri
    'User-Agent' = $UserAgent
}
foreach ($key in $AdditionalHeaders.Keys) { $idxHeaders[$key] = $AdditionalHeaders[$key] }

$introspect = Invoke-IdxJson -Uri "$origin/idp/idx/introspect" -Session $session -Headers $idxHeaders -Body @{ stateToken = $stateToken }
$identify = Get-Remediation -Response $introspect -Name 'identify'
if (-not $identify) { throw 'Okta did not return the identify remediation.' }
$identifyUri = Get-SameOrgUri -Href $identify.href -Origin $origin
$identified = Invoke-IdxJson -Uri $identifyUri -Session $session -Headers $idxHeaders -Body @{ identifier = $UserName; stateHandle = $introspect.stateHandle }

function Find-WebAuthnId {
    param([Parameter(Mandatory)]$Response)
    $candidates = @()
    if ($Response.authenticators.value) { $candidates += @($Response.authenticators.value) }
    if ($Response.authenticatorEnrollments.value) { $candidates += @($Response.authenticatorEnrollments.value) }
    if ($Response.currentAuthenticatorEnrollment.value) { $candidates += @($Response.currentAuthenticatorEnrollment.value) }
    $match = $candidates | Where-Object { $_.key -eq 'webauthn' -and $_.id } | Select-Object -First 1
    if ($match) { return [string]$match.id }
    return $null
}

$passkeyId = Find-WebAuthnId $identified
if (-not $passkeyId) { throw 'Okta did not report an enrolled webauthn authenticator for this user.' }

# Password is optional. If supplied, satisfy the password remediation first because many
# org policies require it before exposing the passkey challenge.
$current = $identified
if ($Password) {
    $passwordRemediation = Get-Remediation -Response $current -Name 'challenge-authenticator'
    if ($passwordRemediation) {
        $passwordUri = Get-SameOrgUri -Href $passwordRemediation.href -Origin $origin
        $current = Invoke-IdxJson -Uri $passwordUri -Session $session -Headers $idxHeaders -Body @{
            credentials = @{ passcode = (ConvertFrom-SecureInput $Password) }
            stateHandle = $current.stateHandle
        }
        $passkeyId = Find-WebAuthnId $current
    }
}

$select = Get-Remediation -Response $current -Name 'select-authenticator-authenticate'
if (-not $select) { throw 'Okta did not offer authenticator selection. Supply -Password if the sign-in policy requires password first.' }
$selectUri = Get-SameOrgUri -Href $select.href -Origin $origin
$challengeResponse = Invoke-IdxJson -Uri $selectUri -Session $session -Headers $idxHeaders -Body @{
    authenticator = @{ id = $passkeyId }
    stateHandle   = $current.stateHandle
}
$challengeData = $challengeResponse.currentAuthenticator.value.contextualData.challengeData
if (-not $challengeData.challenge) { throw 'Okta did not return a WebAuthn challenge.' }

$rpId = if ($RelyingParty) { $RelyingParty } else { $oktaHost }
$rpHash = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($rpId))
$counterBytes = [BitConverter]::GetBytes([uint32]$SignCount)
if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counterBytes) }
$authData = [byte[]]($rpHash + [byte[]]@(0x05) + $counterBytes)
$clientDataJson = [ordered]@{ type = 'webauthn.get'; challenge = [string]$challengeData.challenge; origin = $origin; crossOrigin = $false } | ConvertTo-Json -Compress
$clientDataBytes = [Text.Encoding]::UTF8.GetBytes($clientDataJson)
$clientHash = [System.Security.Cryptography.SHA256]::HashData($clientDataBytes)
$toSignHash = [System.Security.Cryptography.SHA256]::HashData([byte[]]($authData + $clientHash))
Write-Verbose "WebAuthn clientDataJSON: $clientDataJson"
Write-Verbose "WebAuthn authenticatorData (base64): $([Convert]::ToBase64String($authData))"
Write-Verbose "WebAuthn signed digest (base64url): $(ConvertTo-Base64Url $toSignHash)"

$kvToken = Get-KeyVaultToken $KeyVaultAccessToken
$signBody = @{ alg = 'ES256'; value = (ConvertTo-Base64Url $toSignHash) } | ConvertTo-Json
$kvHeaders = @{ Authorization = "Bearer $kvToken"; 'Content-Type' = 'application/json' }
Write-Host 'Signing WebAuthn assertion with Azure Key Vault...' -ForegroundColor Cyan
$signKeyUri = if ($KeyVaultKeyId) {
    $keyIdUri = [Uri]$KeyVaultKeyId
    if ($keyIdUri.Scheme -ne 'https' -or $keyIdUri.Host -ne "$KeyVaultName.vault.azure.net" -or $keyIdUri.AbsolutePath -notmatch '^/keys/[^/]+/[^/]+$') {
        throw 'KeyVaultKeyId must be a versioned HTTPS Key Vault key ID in the selected vault.'
    }
    "$($KeyVaultKeyId.TrimEnd('/'))/sign?api-version=7.4"
} else {
    "https://$keyVaultName.vault.azure.net/keys/$keyVaultKeyName/sign?api-version=7.4"
}
$signResult = Invoke-RestMethod -Method Post -Uri $signKeyUri -Headers $kvHeaders -Body $signBody
$signature = ConvertFrom-IeeeToDer (ConvertFrom-Base64Url $signResult.value)
Write-Verbose "Key Vault signature (base64url IEEE): $($signResult.value)"
Write-Verbose "WebAuthn signature (base64 DER): $([Convert]::ToBase64String($signature))"

$answer = Get-Remediation -Response $challengeResponse -Name 'challenge-authenticator'
if (-not $answer) { throw 'Okta did not return the WebAuthn challenge-answer remediation.' }
$answerUri = Get-SameOrgUri -Href $answer.href -Origin $origin
$success = Invoke-IdxJson -Uri $answerUri -Session $session -Headers $idxHeaders -Body @{
    credentials = @{
        clientData        = [Convert]::ToBase64String($clientDataBytes)
        authenticatorData = [Convert]::ToBase64String($authData)
        signatureData     = [Convert]::ToBase64String($signature)
    }
    stateHandle = $challengeResponse.stateHandle
}
Write-Verbose "Okta assertion response properties: $($success.PSObject.Properties.Name -join ', ')"
Write-Verbose "Okta assertion success remediation: $([string]$success.success.name)"
Write-Verbose "Okta assertion remediations: $(@($success.remediation.value.name) -join ', ')"
Write-Verbose "Okta assertion current authenticator: $([string]$success.currentAuthenticator.value.key) / $([string]$success.currentAuthenticator.value.id)"
if (-not $success.success) {
    $messages = @($success.messages.value.message) -join '; '
    $remaining = @($success.remediation.value.name) -join ', '
    if ($messages) { throw "Okta rejected the assertion: $messages" }
    if ($remaining) { throw "Okta processed the assertion but login is not complete. Remaining remediation(s): $remaining. Supply -Password if this policy requires the password first." }
    throw 'Okta did not return a success remediation after the assertion.'
}

$successUri = Get-SameOrgUri -Href $success.success.href -Origin $origin
$redirectResponse = Invoke-OktaRedirectFirstHop -Uri $successUri -Session $session -Headers $headers
$location = [string]$redirectResponse.Location
Write-Host '✓ Okta accepted the Key Vault-backed passkey assertion.' -ForegroundColor Green
Write-Host "  Success redirect status: $($redirectResponse.StatusCode)" -ForegroundColor Gray
if ($location) { Write-Host '  OAuth/browser redirect was produced.' -ForegroundColor Gray }

[pscustomobject]@{
    Success           = $true
    UserName          = $UserName
    CredentialId      = $CredentialId
    SuccessRedirected = [bool]$location
    RedirectStatus    = $redirectResponse.StatusCode
}
