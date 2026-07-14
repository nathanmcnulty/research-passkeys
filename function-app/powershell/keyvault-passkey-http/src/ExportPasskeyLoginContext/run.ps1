using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
if (-not (Test-DevelopmentSecretExportEnabled)) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Forbidden -NoStore -Body @{success=$false;error='Development secret export is disabled.'}); return }
try {
    $configuration=Get-PasskeyFunctionConfiguration; $recordId=[string]$Request.Params.recordId; $record=Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if (-not $record) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -NoStore -Body @{success=$false;error='Passkey was not found.'}); return }
    $context=Get-PasskeyLoginContext -Configuration $configuration -Record $record
    if ($context.Count -eq 0) { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -NoStore -Body @{success=$false;error='Login context was not found.'}); return }
    Write-Warning "Development login-context export recordId=$recordId"
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body @{success=$true;recordId=$recordId;loginContext=$context})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -NoStore -Body @{success=$false;error=$_.Exception.Message}) }
