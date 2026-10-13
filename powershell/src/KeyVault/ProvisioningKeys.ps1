function New-EntraKeyVaultRegistrationKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [string]$KeyName,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$AccessToken
    )
    if ([string]::IsNullOrWhiteSpace($KeyName)) {
        $prefix = $UserPrincipalName.Split('@')[0] -replace '[^0-9A-Za-z-]', ''
        if (-not $prefix) { $prefix = 'user' }
        $prefix = $prefix.Substring(0, [Math]::Min(12, $prefix.Length))
        $KeyName = "pk-$prefix-$(Get-Random -Minimum 100000 -Maximum 1000000)"
    }
    # Validate the host and path before transmitting the bearer token.
    $reference = Resolve-KeyVaultReference -VaultName $VaultName -KeyName $KeyName
    $body = @{ kty = 'EC'; crv = 'P-256'; key_ops = @('sign', 'verify') } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "https://$($reference.vaultName).vault.azure.net/keys/$($reference.keyName)/create?api-version=7.4" `
        -Method POST -Headers @{ Authorization = "Bearer $AccessToken" } -ContentType 'application/json' `
        -Body $body -MaximumRedirection 0 -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Verbose:$false -Debug:$false -ErrorAction Stop
    $stored = Resolve-KeyVaultReference -VaultName $reference.vaultName -KeyName $reference.keyName -KeyId ([string]$response.key.kid)
    if ([string]$response.key.kid -cnotmatch '/keys/[a-zA-Z0-9-]{1,127}/[a-fA-F0-9]{32}$') { throw 'Key Vault did not return a versioned key ID.' }
    $x = [byte[]](ConvertFrom-Base64Url -Base64Url ([string]$response.key.x))
    $y = [byte[]](ConvertFrom-Base64Url -Base64Url ([string]$response.key.y))
    if ($response.key.kty -ne 'EC' -or $response.key.crv -ne 'P-256' -or $x.Length -ne 32 -or $y.Length -ne 32) {
        throw 'Key Vault did not return an EC P-256 public key with 32-byte coordinates.'
    }
    [pscustomobject]@{ PublicX = $x; PublicY = $y; keyVault = $stored; AccessToken = $AccessToken }
}
