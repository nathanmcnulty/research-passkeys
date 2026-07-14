param($Timer)
. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')
$count=Remove-ExpiredPasskeyCaptureProvenance -Configuration (Get-PasskeyFunctionConfiguration)
Write-Information "Capture provenance cleanup removed $count records."
