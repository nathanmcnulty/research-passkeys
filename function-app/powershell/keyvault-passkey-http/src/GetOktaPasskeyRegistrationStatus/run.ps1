using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $requestId = $null
    if ($null -ne $Request.Params) {
        if ($Request.Params -is [System.Collections.IDictionary]) {
            if ($Request.Params.ContainsKey('requestId')) { $requestId = [string]$Request.Params['requestId'] }
        } else {
            $property = $Request.Params.PSObject.Properties['requestId']
            if ($property) { $requestId = [string]$property.Value }
        }
    }
    if ([string]::IsNullOrWhiteSpace($requestId) -and $TriggerMetadata) {
        $property = $TriggerMetadata.PSObject.Properties['requestId']
        if ($property) { $requestId = [string]$property.Value }
    }
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        $requestId = Get-RequestValue -Body (Get-RequestBodyObject -Request $Request) -Request $Request -Names @('requestId')
    }
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        throw [System.ArgumentException]::new("Missing required route or query value 'requestId'.")
    }
    $configuration = Get-OktaFunctionConfiguration
    $status = Get-RegistrationStatus -RequestId $requestId -Configuration $configuration
    if ($null -eq $status) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::NotFound) -Body ([ordered]@{ success = $false; provider = 'okta'; requestId = $requestId; error = 'Registration request status was not found.' }))
        return
    }
    $status.success = $true
    $status.provider = 'okta'
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body $status)
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadGateway) -Body ([ordered]@{ success = $false; provider = 'okta'; error = $_.Exception.Message }))
}
