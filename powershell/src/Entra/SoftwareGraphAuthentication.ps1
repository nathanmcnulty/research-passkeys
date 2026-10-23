function Resolve-EntraSoftwareGraphTenant {
    param([AllowNull()][string]$TenantId, [Parameter(Mandatory)][string]$UserUpn, [switch]$UseManagedIdentity)
    if ($UseManagedIdentity) { return $TenantId }
    return Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserUpn
}

function Get-EntraSoftwareManagedIdentityToken {
    param([Parameter(Mandatory)][string]$Scope)
    $resource = $Scope -replace '/\.default$', ''
    try {
        # Runtime-only reads. Import never inspects identity endpoints or environment credentials.
        if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
            $uri = [uri]$env:IDENTITY_ENDPOINT
            if ($uri.Host -notin @('127.0.0.1', 'localhost') -or $uri.UserInfo) { throw 'Unexpected managed identity endpoint.' }
            $response = Invoke-RestMethod -Uri "$($uri.AbsoluteUri)?api-version=2019-08-01&resource=$([uri]::EscapeDataString($resource))" `
                -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 30 -MaximumRedirection 0 -Verbose:$false -Debug:$false -ErrorAction Stop
        } else {
            $response = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=$([uri]::EscapeDataString($resource))" `
                -Headers @{ Metadata = 'true' } -ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 30 -MaximumRedirection 0 -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if ([string]::IsNullOrWhiteSpace($response.access_token)) { throw 'Missing token.' }
        return [string]$response.access_token
    } catch { throw 'Managed identity token acquisition failed; sensitive response details suppressed.' }
}

function New-EntraSoftwareCertificateAssertion {
    param([Parameter(Mandatory)][string]$TokenUri, [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$CertificatePath, [AllowNull()][securestring]$CertificatePassword)
    $certificate = $null; $rsa = $null; $password = $null
    try {
        $password = if ($CertificatePassword) { ConvertTo-PlainTextValue $CertificatePassword } else { '' }
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        $now = [DateTimeOffset]::UtcNow
        if (-not $certificate.HasPrivateKey -or $certificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or
            $certificate.NotAfter.ToUniversalTime() -le $now.UtcDateTime) { throw 'Invalid certificate validity or missing private key.' }
        $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = ConvertTo-Base64Url ($certificate.GetCertHash()) } | ConvertTo-Json -Compress
        $payload = @{ aud = $TokenUri; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString()
            nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds() } | ConvertTo-Json -Compress
        $unsigned = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if ($null -eq $rsa) { throw 'An RSA client certificate is required.' }
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $unsigned + '.' + (ConvertTo-Base64Url $signature)
    } catch { throw 'Client certificate assertion failed; sensitive details suppressed.' }
    finally { if ($null -ne $rsa) { $rsa.Dispose() }; if ($null -ne $certificate) { $certificate.Dispose() }; $password = $null }
}

function Get-EntraSoftwareApplicationToken {
    param([Parameter(Mandatory)][string]$Scope, [AllowNull()][string]$TenantId,
        [AllowNull()][string]$ClientId, [AllowNull()][securestring]$ClientSecret,
        [AllowNull()][string]$ClientCertificatePath, [AllowNull()][securestring]$ClientCertificatePassword,
        [switch]$UseManagedIdentity)
    if ($UseManagedIdentity) { return Get-EntraSoftwareManagedIdentityToken -Scope $Scope }
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $secret = $null; $body = @{ client_id = $ClientId; scope = $Scope; grant_type = 'client_credentials' }
    try {
        if ($ClientSecret) {
            $secret = ConvertTo-PlainTextValue $ClientSecret
            if ([string]::IsNullOrWhiteSpace($secret) -or $secret -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
                throw 'ClientSecret must contain the secret value, not its identifier.'
            }
            $body.client_secret = $secret
        } elseif ($ClientCertificatePath) {
            $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $body.client_assertion = New-EntraSoftwareCertificateAssertion -TokenUri $uri -ClientId $ClientId `
                -CertificatePath $ClientCertificatePath -CertificatePassword $ClientCertificatePassword
        } else { throw 'Application authentication requires a secret or certificate.' }
        $response = Invoke-EntraRegistrationRestMethod -Uri $uri -Method POST -Body (ConvertTo-EntraRegistrationForm $body) -ContentType 'application/x-www-form-urlencoded'
        if ([string]::IsNullOrWhiteSpace($response.access_token)) { throw 'Missing token.' }
        return [string]$response.access_token
    } catch { throw 'Application token acquisition failed; sensitive response details suppressed.' }
    finally { $secret = $null; $body = $null }
}
