using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
try {
    $configuration=Get-PasskeyFunctionConfiguration; $recordId=[string]$Request.Params.recordId
    if (-not (Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId)) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -Body @{success=$false;error='Passkey was not found.'}); return }
    $contexts=@(Get-PasskeyCaptureContexts -Configuration $configuration -RecordId $recordId)
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -Body @{success=$true;recordId=$recordId;count=$contexts.Count;contexts=$contexts})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -Body @{success=$false;error=$_.Exception.Message}) }
