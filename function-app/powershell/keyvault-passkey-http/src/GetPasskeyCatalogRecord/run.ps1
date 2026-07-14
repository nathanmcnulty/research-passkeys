using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $recordId = $null
    if ($Request.Params -is [System.Collections.IDictionary] -and $Request.Params.ContainsKey('recordId')) {
        $recordId = [string]$Request.Params['recordId']
    }
    if ([string]::IsNullOrWhiteSpace($recordId) -and $TriggerMetadata) {
        $property = $TriggerMetadata.PSObject.Properties['recordId']
        if ($property) { $recordId = [string]$property.Value }
    }
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        throw [System.ArgumentException]::new("Missing required route or query value 'recordId'.")
    }
    $record = Get-PasskeyCatalogRecord -Configuration (Get-PasskeyFunctionConfiguration) -RecordId $recordId
    if ($null -eq $record) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::NotFound) -Body ([ordered]@{
            success = $false
            recordId = $recordId
            error = 'Passkey was not found.'
        }))
        return
    }
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success = $true
        record = $record
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
