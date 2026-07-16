using namespace System.Net

param($Request, $TriggerMetadata)

. (Join-Path $PSScriptRoot '..\shared\PasskeyFunctionHelpers.ps1')

try {
    $recordId = [string]$Request.Params['recordId']
    $body = if ($Request.Body -is [System.Collections.IDictionary]) { [hashtable]$Request.Body } else { @{} }
    $rpId = [string]$body.rpId
    if ([string]::IsNullOrWhiteSpace($recordId) -or [string]::IsNullOrWhiteSpace($rpId) -or [string]::IsNullOrWhiteSpace([string]$body.clientDataHash)) {
        throw [System.ArgumentException]::new('recordId, rpId, and clientDataHash are required.')
    }
    if ($body.userVerified -isnot [bool]) {
        throw [System.ArgumentException]::new('userVerified must be a boolean.')
    }
    $clientDataHash = ConvertFrom-PasskeyBase64Url -Value ([string]$body.clientDataHash)
    if ($clientDataHash.Length -ne 32) { throw [System.ArgumentException]::new('clientDataHash must contain exactly 32 bytes.') }

    $configuration = Get-PasskeyFunctionConfiguration
    $record = Get-PasskeyCatalogRecord -Configuration $configuration -RecordId $recordId
    if ($null -eq $record) {
        Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::NotFound) -Body @{success=$false;error='Passkey was not found.'})
        return
    }
    if ([string]$record.status -ne 'active') { throw [System.ArgumentException]::new('Passkey is not active.') }
    if ([string]$record.rpId -cne $rpId) { throw [System.UnauthorizedAccessException]::new('The requested RP ID does not match this passkey.') }
    $expectedKeyPrefix = "https://$($configuration.KeyVaultName).vault.azure.net/keys/"
    $keyId = [string]$record.keyVault.keyId
    if (-not $keyId.StartsWith($expectedKeyPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.UnauthorizedAccessException]::new('Passkey signing key is outside the configured Key Vault.')
    }

    $signCount = [int]$record.signCount + 1
    $rpHash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($rpId))
    $counter = [BitConverter]::GetBytes([uint32]$signCount)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
    $authenticatorData = [byte[]]::new(37)
    [Array]::Copy($rpHash, 0, $authenticatorData, 0, 32)
    $authenticatorData[32] = if ([bool]$body.userVerified) { 0x05 } else { 0x01 }
    [Array]::Copy($counter, 0, $authenticatorData, 33, 4)
    $signedBytes = [byte[]]::new(69)
    [Array]::Copy($authenticatorData, 0, $signedBytes, 0, 37)
    [Array]::Copy($clientDataHash, 0, $signedBytes, 37, 32)
    $digest = [System.Security.Cryptography.SHA256]::HashData($signedBytes)
    $signResponse = Invoke-RestMethod -Method POST -Uri "$keyId/sign?api-version=7.4" `
        -Headers @{Authorization="Bearer $(Get-KeyVaultAccessToken -Configuration $configuration)"} `
        -ContentType 'application/json' -Body (@{alg='ES256';value=(ConvertTo-PasskeyBase64Url -Bytes $digest)} | ConvertTo-Json -Compress)
    $signatureBytes = ConvertFrom-PasskeyBase64Url -Value ([string]$signResponse.value)
    if ($signatureBytes.Length -ne 64) { throw 'Key Vault returned an invalid ES256 signature.' }

    $record.signCount = $signCount
    $record.updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    Update-PasskeyCatalogRecord -Record $record -Configuration $configuration
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::OK) -Body ([ordered]@{
        success=$true;recordId=$recordId;signCount=$signCount
        authenticatorData=(ConvertTo-PasskeyBase64Url -Bytes $authenticatorData)
        signature=[string]$signResponse.value;signatureFormat='ieee-p1363'
    }))
} catch [System.ArgumentException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body @{success=$false;error=$_.Exception.Message})
} catch [System.UnauthorizedAccessException] {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::Forbidden) -Body @{success=$false;error=$_.Exception.Message})
} catch {
    Push-OutputBinding -Name Response -Value (New-JsonHttpResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body @{success=$false;error=$_.Exception.Message})
}
