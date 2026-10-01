using namespace System.Net
param($Request,$TriggerMetadata)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotImplemented -NoStore -Body @{
    success = $false
    error = 'Legacy Key Vault passkey mutations are disabled pending broker lifecycle controls.'
})
