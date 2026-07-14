using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
try {
    $configuration=Get-OktaFunctionConfiguration; $recordId=[string]$Request.Params.recordId; $record=Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if (-not $record -or $record.provider -ne 'okta') { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -Body @{success=$false;error='Okta passkey was not found.'}); return }
    $context=Get-PasskeyLoginContext -Configuration $configuration -Record $record
    $parameters=@{OktaDomain=(Resolve-OktaDomain -Body @{} -Request ([pscustomobject]@{Query=@{}}));UserName=[string]$record.userName;CredentialId=[string]$record.credentialId;KeyVaultName=$configuration.KeyVaultName;KeyVaultKeyName=[string]$record.keyVault.keyName;KeyVaultAccessToken=(Get-KeyVaultAccessToken -Configuration $configuration);UserAgent=(Normalize-PasskeyUserAgent $context.userAgent)}
    if ($context.password) { $parameters.Password=ConvertTo-SecureString ([string]$context.password) -AsPlainText -Force }
    if ($record.rpId) { $parameters.RelyingParty=[string]$record.rpId }
    $redirectUri=[Environment]::GetEnvironmentVariable('PASSKEY_OKTA_REDIRECT_URI');if($redirectUri){$parameters.RedirectUri=$redirectUri}
    $result=& (Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\okta\Invoke-OktaPasskeyLogin.ps1') @parameters | Select-Object -Last 1
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -Body @{success=$true;provider='okta';recordId=$recordId;result=$result})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode BadGateway -Body @{success=$false;error=$_.Exception.Message}) }
