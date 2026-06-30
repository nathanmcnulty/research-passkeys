using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = Get-RequestBodyObject -Request $Request
    $userPrincipalName = Get-RequestValue -Body $body -Request $Request -Names @('userPrincipalName', 'email')
    $estsAuthCookie = Get-RequestValue -Body $body -Request $Request -Names @('estsAuth', 'estsAuthCookie')
    $displayName = Get-RequestValue -Body $body -Request $Request -Names @('displayName', 'passkeyDisplayName')
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName')

    if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
        throw [System.ArgumentException]::new("Missing required field 'userPrincipalName' or 'email'.")
    }

    if ([string]::IsNullOrWhiteSpace($estsAuthCookie)) {
        throw [System.ArgumentException]::new("Missing required field 'estsAuth' or 'estsAuthCookie'.")
    }

    $configuration = Get-PasskeyFunctionConfiguration
    $keyVaultAccessToken = Get-KeyVaultAccessToken -Configuration $configuration
    $scriptPath = Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\reference\Register-KeyVaultPasskeyViaESTSAuth.ps1'
    $outputPath = New-TempOutputPath -UserPrincipalName $userPrincipalName -AuthMethod 'estsauth'

    $scriptParameters = @{
        ESTSAuthCookie = $estsAuthCookie
        TenantId = $configuration.TenantId
        KeyVaultName = $configuration.KeyVaultName
        KeyVaultAccessToken = $keyVaultAccessToken
        OutputPath = $outputPath
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        $scriptParameters.PasskeyDisplayName = $displayName
    }

    if (-not [string]::IsNullOrWhiteSpace($keyVaultKeyName)) {
        $scriptParameters.KeyVaultKeyName = $keyVaultKeyName
    }

    $credential = Invoke-PasskeyRegistrationScript -ScriptPath $scriptPath -Parameters $scriptParameters
    if ([string]::Compare([string]$credential.userName, $userPrincipalName, $true) -ne 0) {
        throw [System.InvalidOperationException]::new("The ESTSAUTH cookie resolved to '$($credential.userName)', which does not match the requested user '$userPrincipalName'.")
    }

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        authMethod = 'estsauth'
        tenantId = $configuration.TenantId
        keyVaultName = $configuration.KeyVaultName
        credential = $credential
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body ([ordered]@{
        success = $false
        error = $_.Exception.Message
    }))
}
