using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
if (-not (Test-DevelopmentSecretExportEnabled)) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Forbidden -NoStore -Body @{success=$false;error='Development secret export is disabled.'}); return }
try {
    $configuration=Get-PasskeyFunctionConfiguration; $recordId=[string]$Request.Params.recordId; $captureId=[string]$Request.Params.captureId
    $context=@(Get-PasskeyCaptureContexts -Configuration $configuration -RecordId $recordId) | Where-Object captureId -eq $captureId | Select-Object -First 1
    if (-not $context) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -NoStore -Body @{success=$false;error='Capture context was not found.'}); return }
    $capture=Export-PasskeyCapturePayload -Configuration $configuration -Context $context
    Write-Warning "Development capture export recordId=$recordId captureId=$captureId"
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body @{success=$true;recordId=$recordId;captureId=$captureId;capture=$capture})
} catch [TimeoutException] { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Gone -NoStore -Body @{success=$false;error='Capture context has expired.'})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -NoStore -Body @{success=$false;error=$_.Exception.Message}) }
