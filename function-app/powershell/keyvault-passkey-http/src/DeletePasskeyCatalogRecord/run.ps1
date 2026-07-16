using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $recordId = [string]$Request.Params.recordId
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        throw [System.ArgumentException]::new("Missing required route value 'recordId'.")
    }

    $configuration = Get-PasskeyFunctionConfiguration
    $record = Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if ($null -eq $record) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode NotFound -NoStore -Body @{
            success = $false
            error = 'Passkey was not found.'
        })
        return
    }

    $deletedLoginContext = $false
    if (-not [string]::IsNullOrWhiteSpace([string]$record.loginContextSecretName)) {
        $deletedLoginContext = Remove-PasskeyKeyVaultSecret -Configuration $configuration -Name ([string]$record.loginContextSecretName)
    }
    $deletedKey = Remove-PasskeyKeyVaultKey -Configuration $configuration -KeyVault ([hashtable]$record.keyVault)
    $deletedCatalog = Remove-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body ([ordered]@{
        success = $true
        recordId = $recordId
        status = 'deleted'
        catalogDeleted = $deletedCatalog
        loginContextDeleted = $deletedLoginContext
        keyDeleted = $deletedKey
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode BadRequest -NoStore -Body @{
        success = $false
        error = $_.Exception.Message
    })
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode InternalServerError -NoStore -Body @{
        success = $false
        error = $_.Exception.Message
    })
}
