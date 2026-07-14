using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

Invoke-ProviderPasskeyLookup -Request $Request -TriggerMetadata $TriggerMetadata -Provider okta
