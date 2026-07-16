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
    if ([string]$record.status -ne 'active') {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode Conflict -NoStore -Body @{
            success = $false
            error = 'Passkey is not active.'
        })
        return
    }

    $context = Get-PasskeyLoginContext -Configuration $configuration -Record $record
    $userAgent = $null
    if ($context.ContainsKey('userAgent') -and -not [string]::IsNullOrWhiteSpace([string]$context.userAgent)) {
        $userAgent = Normalize-PasskeyUserAgent -UserAgent $context.userAgent
    }

    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode OK -NoStore -Body ([ordered]@{
        success = $true
        browserContext = [ordered]@{
            provider = [string]$record.provider
            rpId = [string]$record.rpId
            userName = [string]$record.userName
            userAgent = $userAgent
        }
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
