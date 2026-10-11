function Invoke-KeyVaultPasskeySignHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$KeyVaultInfo,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][byte[]]$Digest
    )
    if ($Digest.Length -ne 32) { throw 'ES256 signing requires a SHA-256 digest.' }
    if ([string]::IsNullOrWhiteSpace($AccessToken)) { throw 'Key Vault signing requires an access token.' }
    $key = Resolve-KeyVaultReference -VaultName $KeyVaultInfo.vaultName -KeyName $KeyVaultInfo.keyName -KeyId $KeyVaultInfo.keyId
    $uri = "$($key.keyId)/sign?api-version=7.4"
    $headers = @{ Authorization="Bearer $AccessToken"; 'Content-Type'='application/json' }
    $body = @{alg='ES256';value=(ConvertTo-Base64Url $Digest)} | ConvertTo-Json -Compress
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -MaximumRedirection 0 -ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 30 -Verbose:$false -Debug:$false -ErrorAction Stop
        } catch {
            if ($attempt -eq 3) { throw 'Key Vault signing failed; details suppressed.' }
            Start-Sleep -Milliseconds (250 * [math]::Pow(2,$attempt - 1))
            continue
        }
        # Malformed signatures are a protocol error, never a reason to try a local key.
        if ($response.value -isnot [string] -or [string]::IsNullOrWhiteSpace($response.value)) { throw 'Key Vault returned an invalid ES256 signature.' }
        try { $raw = ConvertFrom-Base64Url $response.value } catch { throw 'Key Vault returned an invalid ES256 signature.' }
        if ($raw.Length -ne 64) { throw 'Key Vault returned an invalid ES256 signature length.' }
        return ,(ConvertFrom-IeeeToDer $raw)
    }
}
