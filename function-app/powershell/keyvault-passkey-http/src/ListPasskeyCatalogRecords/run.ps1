using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $body = @{}
    $provider = Get-RequestValue -Body $body -Request $Request -Names @('provider')
    $rpId = Get-RequestValue -Body $body -Request $Request -Names @('rpId', 'relyingParty')
    $userName = Get-RequestValue -Body $body -Request $Request -Names @('userName', 'username', 'email')
    $status = Get-RequestValue -Body $body -Request $Request -Names @('status')
    $credentialId = Get-RequestValue -Body $body -Request $Request -Names @('credentialId')
    $displayName = Get-RequestValue -Body $body -Request $Request -Names @('displayName')
    $keyVaultKeyName = Get-RequestValue -Body $body -Request $Request -Names @('keyVaultKeyName', 'keyName')
    if ($provider -and $provider -notin @('entra', 'okta')) {
        throw [System.ArgumentException]::new("provider must be 'entra' or 'okta'.")
    }
    if ($status -and $status -notin @('active', 'disabled', 'deleted')) {
        throw [System.ArgumentException]::new("status must be 'active', 'disabled', or 'deleted'.")
    }
    $records = @(Get-PasskeyCatalogRecords -Configuration (Get-PasskeyFunctionConfiguration) `
        -Provider ([string]($provider ?? '')) -RpId $rpId -UserName $userName -Status ([string]($status ?? '')) `
        -CredentialId $credentialId -DisplayName $displayName -KeyVaultKeyName $keyVaultKeyName)
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        count = $records.Count
        records = $records
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
