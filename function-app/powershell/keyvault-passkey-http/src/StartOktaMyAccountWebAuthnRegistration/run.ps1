using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $domain = Resolve-OktaDomain -Body $body -Request $Request
    $accessToken = Resolve-OktaAccessToken -Body $body -Request $Request
    $origin = if ($domain -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $domain.TrimEnd('/') } else { "https://$($domain.TrimEnd('/'))" }
    $originUri = [Uri]$origin
    if ($originUri.Scheme -ne 'https' -or $originUri.AbsolutePath -ne '/' -or $originUri.Query -or $originUri.Fragment -or $originUri.UserInfo) {
        throw [System.ArgumentException]::new("Okta domain must be an HTTPS host name only.")
    }

    $registration = Invoke-RestMethod -Method Post -Uri "$($originUri.AbsoluteUri.TrimEnd('/'))/idp/myaccount/webauthn/registration" -Headers @{
        Authorization = "Bearer $accessToken"
        Accept = 'application/json; okta-version=1.0.0'
        'Content-Type' = 'application/json'
    } -Body '{}'

    if (-not $registration.options.challenge -or -not $registration.expiresAt) {
        throw [System.InvalidOperationException]::new('Okta returned an unexpected MyAccount registration response.')
    }

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        provider = 'okta'
        origin = $originUri.AbsoluteUri.TrimEnd('/')
        registration = $registration
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{
        success = $false
        provider = 'okta'
        error = $_.Exception.Message
    }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{
        success = $false
        provider = 'okta'
        error = $_.Exception.Message
    }))
}
