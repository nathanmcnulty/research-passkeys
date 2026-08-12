using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::NotImplemented) -Body @{
    success = $false
    error = 'Software-backed assertions are disabled because this service cannot prove fresh user presence or verification.'
})
