$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\powershell\keyvault-passkey-http\src\shared\PasskeyFunctionHelpers.ps1')

foreach ($body in @(@{}, @{ accessToken = '  ' }, @{ accessToken = @{ token = 'wrong-type' } })) {
    $rejected = $false
    try {
        Resolve-OktaAccessToken -Body $body | Out-Null
    } catch [System.ArgumentException] {
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'Missing or nonstring Okta body token was accepted.'
    }
}

if ((Resolve-OktaAccessToken -Body @{ oktaAccessToken = ' okta-user-token ' }) -cne 'okta-user-token') {
    throw 'Explicit Okta body token was not selected.'
}

$response = New-JsonHttpResponse -StatusCode ([System.Net.HttpStatusCode]::OK) -Body @{ success = $true }
if ($response.Headers['Cache-Control'] -cne 'no-store' -or $response.Headers['Pragma'] -cne 'no-cache') {
    throw 'JSON response omitted non-cacheable headers.'
}

Write-Output 'PowerShell Okta token and no-store boundaries passed.'
