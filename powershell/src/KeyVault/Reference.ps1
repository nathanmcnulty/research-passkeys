function Resolve-KeyVaultReference {
    param(
        [string]$VaultName,
        [string]$KeyName,
        [string]$KeyId
    )

    $resolvedVaultName = Normalize-OptionalString $VaultName
    $resolvedKeyName = Normalize-OptionalString $KeyName
    $resolvedKeyId = Normalize-OptionalString $KeyId

    # Match the original text before URI normalization can hide escaped or dot segments.
    # Public Azure only: sovereign-cloud vaults require a separately reviewed audience/host policy.
    $referenceValue = if ($resolvedKeyId) { $resolvedKeyId } elseif ($resolvedKeyName -match '^https?://') { $resolvedKeyName } else { $null }
    if ($referenceValue) {
        if ($referenceValue -cnotmatch '^https://([a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9])\.vault\.azure\.net(?::443)?/keys/([a-zA-Z0-9-]{1,127})(?:/([a-fA-F0-9]{32}))?$') {
            throw 'Invalid Key Vault key reference: expected an HTTPS public-Azure vault key URL.'
        }
        $urlVault = $Matches[1]
        $urlKey = $Matches[2]
        $urlVersion = $Matches[3]
        if (($resolvedVaultName -and $resolvedVaultName -ine $urlVault) -or
            ($resolvedKeyName -and $resolvedKeyName -notmatch '^https?://' -and $resolvedKeyName -cne $urlKey) -or
            ($resolvedKeyId -and $resolvedKeyName -match '^https?://' -and $resolvedKeyName -cne $resolvedKeyId)) {
            throw 'Key Vault metadata conflicts with keyId. Refusing to change the registered signing key.'
        }
        $resolvedVaultName = $urlVault.ToLowerInvariant()
        $resolvedKeyName = $urlKey
        $resolvedKeyId = "https://$resolvedVaultName.vault.azure.net/keys/$resolvedKeyName"
        if ($urlVersion) { $resolvedKeyId += "/$urlVersion" }
    }
    if ($resolvedVaultName -cnotmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$' -or $resolvedVaultName -match '--' -or
        $resolvedKeyName -cnotmatch '^[a-zA-Z0-9-]{1,127}$') {
        throw 'Invalid or incomplete Key Vault vaultName/keyName.'
    }
    if (-not $resolvedKeyId) {
        $resolvedKeyId = "https://$($resolvedVaultName.ToLowerInvariant()).vault.azure.net/keys/$resolvedKeyName"
    }
    return @{ vaultName = $resolvedVaultName; keyName = $resolvedKeyName; keyId = $resolvedKeyId }
}
