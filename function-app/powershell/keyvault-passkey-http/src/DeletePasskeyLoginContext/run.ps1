using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
try{
 $configuration=Get-PasskeyFunctionConfiguration;$recordId=[string]$Request.Params.recordId;$record=Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
 if(-not $record){Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -Body @{success=$false;error='Passkey was not found.'});return}
 $deleted=$false;if($record.loginContextSecretName){$deleted=Remove-PasskeyKeyVaultSecret -Configuration $configuration -Name ([string]$record.loginContextSecretName)}
 $record.relyingParty=$record.rpId;$record[$record.provider]=$record.providerMetadata;$extensions=@{loginContextSecretName=$null;hasStoredPassword=$false;hasStoredUserAgent=$false};if($record.latestCaptureId){$extensions.latestCaptureId=$record.latestCaptureId};[void](Save-PasskeyCatalogRecord -Provider $record.provider -Credential $record -Configuration $configuration -Extensions $extensions)
 Write-Warning "Login context deletion recordId=$recordId deleted=$deleted";Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -Body @{success=$true;recordId=$recordId;deleted=$deleted})
}catch{Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -Body @{success=$false;error=$_.Exception.Message})}
