using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $requestId = $null

    if ($null -ne $Request.Params) {
        if ($Request.Params -is [System.Collections.IDictionary]) {
            if ($Request.Params.ContainsKey('requestId')) {
                $requestId = [string]$Request.Params['requestId']
            }
        } else {
            $requestIdProperty = $Request.Params.PSObject.Properties['requestId']
            if ($requestIdProperty) {
                $requestId = [string]$requestIdProperty.Value
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($requestId) -and $TriggerMetadata) {
        $triggerRequestIdProperty = $TriggerMetadata.PSObject.Properties['requestId']
        if ($triggerRequestIdProperty) {
            $requestId = [string]$triggerRequestIdProperty.Value
        }
    }

    if ([string]::IsNullOrWhiteSpace($requestId)) {
        $body = Get-RequestBodyObject -Request $Request
        $requestId = Get-RequestValue -Body $body -Request $Request -Names @('requestId')
    }

    if ([string]::IsNullOrWhiteSpace($requestId)) {
        throw [System.ArgumentException]::new("Missing required route or query value 'requestId'.")
    }

    $status = Get-RegistrationStatus -RequestId $requestId
    if ($null -eq $status) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::NotFound) -Body ([ordered]@{
            success = $false
            requestId = $requestId
            error = 'Registration request status was not found.'
        }))
        return
    }

    $status.success = $true
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body $status)
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
