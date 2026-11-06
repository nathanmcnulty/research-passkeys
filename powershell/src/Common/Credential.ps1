function Assert-CredentialData {
    param([AllowNull()]$Data)
    if ($Data -isnot [System.Collections.IDictionary]) { throw 'Credential JSON must contain one object.' }
    foreach ($name in @('username', 'userName', 'userPrincipalName', 'userHandle', 'credentialId', 'relyingParty', 'rpId', 'url', 'privateKey', 'keyValue')) {
        if ($Data.Contains($name) -and ($Data[$name] -isnot [string] -or [string]::IsNullOrWhiteSpace($Data[$name]))) {
            throw "Credential property '$name' must be a nonempty string."
        }
    }
    foreach ($name in @('signCount', 'counter')) {
        if ($Data.Contains($name) -and ($Data[$name] -isnot [long] -and $Data[$name] -isnot [int] -or
            $Data[$name] -lt 0 -or $Data[$name] -gt [uint32]::MaxValue)) {
            throw "Credential property '$name' must be a uint32 integer."
        }
    }
    if ($Data.Contains('keyVault')) {
        if ($Data.keyVault -isnot [System.Collections.IDictionary]) { throw 'Credential keyVault must be an object.' }
        foreach ($name in @('vaultName', 'keyName', 'keyId')) {
            if ($Data.keyVault.Contains($name) -and ($Data.keyVault[$name] -isnot [string] -or [string]::IsNullOrWhiteSpace($Data.keyVault[$name]))) {
                throw "Credential keyVault property '$name' must be a nonempty string."
            }
        }
        $null = Resolve-KeyVaultReference -VaultName $Data.keyVault.vaultName -KeyName $Data.keyVault.keyName -KeyId $Data.keyVault.keyId
    }
}
