using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
try {
    $configuration=Get-PasskeyFunctionConfiguration; $recordId=[string]$Request.Params.recordId; $captureId=[string]$Request.Params.captureId
    $context=@(Get-PasskeyCaptureContexts -Configuration $configuration -RecordId $recordId) | Where-Object captureId -eq $captureId | Select-Object -First 1
    if (-not $context) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -Body @{success=$false;error='Capture context was not found.'}); return }
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -Body @{success=$true;context=$context})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -Body @{success=$false;error=$_.Exception.Message}) }
