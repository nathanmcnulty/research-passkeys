using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
try {
    $configuration=Get-PasskeyFunctionConfiguration; $recordId=[string]$Request.Params.recordId; $record=Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if (-not $record -or $record.provider -ne 'entra') { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -Body @{success=$false;error='Entra passkey was not found.'}); return }
    $context=Get-PasskeyLoginContext -Configuration $configuration -Record $record; $record.keyVault.vaultName=$configuration.KeyVaultName
    $parameters=@{KeyVaultAccessToken=(Get-KeyVaultAccessToken -Configuration $configuration);KeyVaultTenantId=$configuration.TenantId;UserAgent=(Normalize-PasskeyUserAgent $context.userAgent)}
    $login=Invoke-PasskeyLoginScript -ScriptPath (Join-Path $PSScriptRoot '..\shared\passkey-assets\scripts\entra\reference\Invoke-EntraPasskeyLogin.ps1') -Credential $record -Parameters $parameters
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body @{success=[bool]$login.Result.Success;provider='entra';recordId=$recordId;userPrincipalName=$login.Result.UserPrincipalName;estsAuth=$login.ESTSAuthCookie})
} catch { Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -NoStore -Body @{success=$false;error=$_.Exception.Message}) }
